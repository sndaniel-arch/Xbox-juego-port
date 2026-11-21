/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <algorithm>

#include <rex/assert.h>
#include <rex/math.h>
#include <rex/ui/graphics_upload_buffer_pool.h>

namespace rex {
namespace ui {

namespace {

// (Ronda 5, C-R5-06.) A writable page that has not been the current page
// for this many completed submissions is high-water left over from a
// spike (zone load, shader preload, big texture upload), not working
// set: the steady-state pages are re-used every submission, so they
// never go this long without being written. 120 submissions is ~2 s at
// 60 fps / ~1 s at 120 fps -- long enough that a page idle for that
// long is not coming back next frame, short enough that the memory is
// actually returned while the game is still running. Pages whose index
// is 0 are never freed: ChangeSubmissionTimeline() marks every page 0,
// so 0 means "age unknown in this timeline", not "idle".
constexpr uint64_t kUnusedPageShrinkSubmissions = 120;

}  // namespace

GraphicsUploadBufferPool::~GraphicsUploadBufferPool() {
  ClearCache();
}

void GraphicsUploadBufferPool::Reclaim(uint64_t completed_submission_index) {
  while (submitted_first_) {
    if (submitted_first_->last_submission_index_ > completed_submission_index) {
      break;
    }
    if (writable_last_) {
      writable_last_->next_ = submitted_first_;
    } else {
      writable_first_ = submitted_first_;
    }
    writable_last_ = submitted_first_;
    submitted_first_ = submitted_first_->next_;
    writable_last_->next_ = nullptr;
  }
  if (!submitted_first_) {
    submitted_last_ = nullptr;
  }

  // (Ronda 5, C-R5-06.) Shrink the high-water: free writable spare pages
  // (never the current page, writable_first_, which Request() is filling)
  // that have not been used for kUnusedPageShrinkSubmissions. Writable
  // pages are not referenced by any in-flight GPU work -- they were
  // reclaimed above once the GPU finished them, or never submitted in
  // this timeline -- so deleting them frees the VkBuffer and its memory
  // immediately (VulkanPage owns both). The working set is untouched: a
  // page in steady use is re-written every submission and never ages
  // out. If the workload needs the page again later it is simply
  // re-created by Request(), one page at a time. Reclaim() runs once per
  // completed submission on the command processor thread, so this costs
  // one short list walk per frame and no locking.
  Page* previous = writable_first_;
  Page* page = previous ? previous->next_ : nullptr;
  while (page) {
    Page* next = page->next_;
    if (page->last_submission_index_ != 0 &&
        page->last_submission_index_ + kUnusedPageShrinkSubmissions <
            completed_submission_index) {
      previous->next_ = next;
      if (page == writable_last_) {
        writable_last_ = previous;
      }
      delete page;
    } else {
      previous = page;
    }
    page = next;
  }
}

void GraphicsUploadBufferPool::ChangeSubmissionTimeline() {
  // Reclaim all submitted pages.
  if (writable_last_) {
    writable_last_->next_ = submitted_first_;
  } else {
    writable_first_ = submitted_first_;
  }
  writable_last_ = submitted_last_;
  submitted_first_ = nullptr;
  submitted_last_ = nullptr;

  // Mark all pages as never used yet in the new timeline.
  Page* page = writable_first_;
  while (page) {
    page->last_submission_index_ = 0;
    page = page->next_;
  }
}

void GraphicsUploadBufferPool::ClearCache() {
  // Called from the destructor - must not call virtual functions here.
  current_page_flushed_ = 0;
  current_page_used_ = 0;
  while (submitted_first_) {
    Page* next_ = submitted_first_->next_;
    delete submitted_first_;
    submitted_first_ = next_;
  }
  submitted_last_ = nullptr;
  while (writable_first_) {
    Page* next_ = writable_first_->next_;
    delete writable_first_;
    writable_first_ = next_;
  }
  writable_last_ = nullptr;
}

GraphicsUploadBufferPool::Page::~Page() {}

void GraphicsUploadBufferPool::FlushWrites() {
  if (current_page_flushed_ >= current_page_used_) {
    return;
  }
  assert_not_null(writable_first_);
  FlushPageWrites(writable_first_, current_page_flushed_,
                  current_page_used_ - current_page_flushed_);
  current_page_flushed_ = current_page_used_;
}

GraphicsUploadBufferPool::Page* GraphicsUploadBufferPool::Request(uint64_t submission_index,
                                                                  size_t size, size_t alignment,
                                                                  size_t& offset_out) {
  alignment = std::max(alignment, size_t(1));
  assert_true(rex::is_pow2(alignment));
  size = rex::align(size, alignment);
  assert_true(size <= page_size_);
  if (size > page_size_) {
    return nullptr;
  }
  assert_true(!current_page_used_ || submission_index >= writable_first_->last_submission_index_);
  assert_true(!submitted_last_ || submission_index >= submitted_last_->last_submission_index_);
  size_t current_page_used_aligned = rex::align(current_page_used_, alignment);
  if (current_page_used_aligned + size > page_size_ || !writable_first_) {
    // Start a new page if can't fit all the bytes or don't have an open page.
    if (writable_first_) {
      // Close the page that was current.
      FlushWrites();
      if (submitted_last_) {
        submitted_last_->next_ = writable_first_;
      } else {
        submitted_first_ = writable_first_;
      }
      submitted_last_ = writable_first_;
      writable_first_ = writable_first_->next_;
      submitted_last_->next_ = nullptr;
      if (!writable_first_) {
        writable_last_ = nullptr;
      }
    }
    if (!writable_first_) {
      // Create a new page if none available.
      writable_first_ = CreatePageImplementation();
      if (!writable_first_) {
        // Failed to create.
        return nullptr;
      }
      writable_first_->last_submission_index_ = submission_index;
      writable_first_->next_ = nullptr;
      writable_last_ = writable_first_;
      // After CreatePageImplementation (more specifically, the first successful
      // call), page_size_ may grow - but this doesn't matter here.
    }
    current_page_used_ = 0;
    current_page_used_aligned = 0;
    current_page_flushed_ = 0;
  }
  writable_first_->last_submission_index_ = submission_index;
  offset_out = current_page_used_aligned;
  current_page_used_ = current_page_used_aligned + size;
  return writable_first_;
}

GraphicsUploadBufferPool::Page* GraphicsUploadBufferPool::RequestPartial(uint64_t submission_index,
                                                                         size_t size,
                                                                         size_t alignment,
                                                                         size_t& offset_out,
                                                                         size_t& size_out) {
  alignment = std::max(alignment, size_t(1));
  assert_true(rex::is_pow2(alignment));
  size = rex::align(size, alignment);
  size = std::min(size, page_size_);
  size_t current_page_used_aligned = rex::align(current_page_used_, alignment);
  if (current_page_used_aligned + alignment <= page_size_) {
    size = std::min(size, (page_size_ - current_page_used_aligned) & ~(alignment - 1));
  }
  Page* page = Request(submission_index, size, alignment, offset_out);
  if (!page) {
    return nullptr;
  }
  size_out = size;
  return page;
}

void GraphicsUploadBufferPool::FlushPageWrites(Page* page, size_t offset, size_t size) {}

}  // namespace ui
}  // namespace rex
