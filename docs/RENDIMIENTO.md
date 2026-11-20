# Rendimiento — objetivo: 100% jugable a 60 fps en Android

**Fecha:** 2026-11-13.
**Decisión del usuario:** el port debe ser 100% jugable en Android y optimizado;
si el original corría a 60 fps, el port también debe correr a 60 fps.

## La meta

- **100% jugable**: de principio a fin, todo el contenido (historia, DLCs,
  logros, guardados), no solo el menú o el primer nivel.
- **60 fps sostenidos en juego** (no solo en el menú), a **720p** — la
  resolución nativa de la versión de Xbox 360.
- **Presupuesto por frame: 16,6 ms.** Todo lo que se mida, se mide contra eso.

## Por qué 60 fps es realista (y no un deseo)

- La versión de Xbox 360 corría a **720p y 60 fps estables** (Digital Foundry).
- el motor es un juego 2D/2.5D pintado a mano: ligero de GPU comparado con un
  3D. El original pedía una GeForce 8800 GT (2007) en PC.
- La CPU es nativa desde el primer día (el código PowerPC se recompila a
  ARM64); no hay emulación de CPU que se coma los frames.
- Los ports hermanos lo logran: Origins a 60 fps en Galaxy S23, Legends a 60
  fps en Snapdragon 845.

## Cómo se llega a 60 fps

1. **Cap de 60 fps** opcional como cap de vblank del guest (el launcher
   trae el selector 30/60/sin límite; **por defecto sin límite**: con el
   cap en 0 no se emite `REX_FPS_CAP` y el vblank del guest — 60 Hz por
   defecto — pauta el juego igualmente). Sin cap, el juego no puede
   dormirse entre frames.
2. **Escala de resolución**: 720p de objetivo; **540p como fallback manual**
   en GPUs débiles (el usuario lo elige en el diálogo de gráficos, modo
   960×540; no hay bajada automática). La escala baja es mejor
   que perder frames.
3. **Presets Performance / Balanced / Accuracy** (los del launcher de
   rexauto): Performance por defecto en gama media, Accuracy solo en gama
   alta.
4. **Shaders bajo demanda, no precompilación total**: precompilar todos los
   shaders al arrancar costaba 1,5–2,5 min de pantalla negra. En el port:
   compilar al usar, con caché persistente, y nunca bloquear el primer frame.
5. **Perfiles por GPU + detección automática** (como Zandatsu): Adreno,
   Mali, Xclipse y otros. La detección elige el .so del driver
   (`GpuDriver.pickLibrary()`: PanVK en Mali, Turnip en Adreno) y los
   ajustes aplican un perfil Mali en tiempo de ejecución
   (`GraphicsSettings.asCvars()`: sin consultas de oclusión ni MSAA 2×
   nativo en Mali, salvo preset accuracy). El plugin de GPU emulada
   (`librexgpu-xenos.so`, `--gpu_plugin=xenos`) se elige al arrancar; si
   el renderer nativo pierde el dispositivo, el runtime aborta con
   `FatalError` — no hay cambio automático a otro backend en caliente.
6. **Capa de validación de Vulkan desde el primer día** (no al final): es el
   único procedimiento que ha convertido un "bug Mali" en "bug nuestro,
   arreglado" (NFSMW 0.5.5). Objetivo: cero avisos de sincronización.

> **Nota — "Double Buffer" no existe como artefacto en este port.** El
> buffering lo decide el swapchain (FIFO/FIFO_RELAXED, configurado en el
> launcher); FIFO es el equivalente del Double Buffer clásico (vsync con
> cola, sin tearing). No hay ningún cvar ni ajuste llamado "double
> buffer": si el objetivo exige Double Buffer explícito, falta
> implementarlo o aceptar esta equivalencia.

## El caso difícil: Mali-G57 (el teléfono del usuario)

El riesgo de rendimiento no es Adreno (ahí 60 fps es lo esperado) sino Mali,
donde el driver pierde el dispositivo a los ~4 s (Zandatsu KNOWN_ISSUES).
Lo que sigue NO es un perfil Mali-G57 aplicado: no existe detección por
GPU ni bundle Mali en el launcher. Es una checklist de 12 puntos de
referencia (con precedente verificado en otros ports): una parte vive como
defaults globales del launcher, otra sigue sin verificar en este port.
Nada de esto se aplica solo al detectar una G57.

De los 12, solo los puntos 5 (sin MSAA 2×) y 7 (sin oclusión) son
interruptores en tiempo de ejecución y se aplican en
`GraphicsSettings.asCvars()` cuando la GPU es Mali (y el preset no es
accuracy); el punto 3 se aplica en parte (vertex stores off siempre;
fragment stores solo se relaja con un driver PanVK seleccionado). El
resto son restricciones de compilación, traductor o driver, no ajustes
que el launcher cambie por GPU.

1. Vulkan 1.1 + `VK_EXT_descriptor_indexing`; SPIR-V rebajado a 1.3
   (sin verificar en este port).
2. Máximo **4 descriptor sets** (con 5, el driver cae en
   `vkCreatePipelineLayout`) — sin verificar en este port.
3. Sin buffer device address, sin `vertexPipelineStoresAndAtomics`
   (este último es el crash de Legends issue #7 en Mali-G57; `false`
   como default global en el launcher). "Sin `shaderInt64`" es ausencia
   por omisión en el código propio (0 menciones fuera de thirdparty),
   no un ajuste de ningún perfil.
4. Texturas BC decodificadas en CPU (la G57 no tiene BC/DXT).
5. Sin MSAA 2× (el hardware no lo anuncia; 4× o nada, o FXAA/CAS).
6. Validación de Vulkan en todas las pruebas.
7. Sin consultas de oclusión en Mali.
8. Vida de recursos serializada (cola retenida, pipelines uno a uno, salto
   tras 2 caídas en el mismo shader, interruptor de "render compatible").
9. Flush/invalidación a mano en memoria compartida CPU↔GPU.
10. Render targets sin formato mutable (para que el driver comprima con
    AFBC).
11. No llenar el tiler (resolución interna baja; PanVK no salva tiler-OOM
    en G57).
12. SDL3 con el parche del 11-nov-2026 (crash en `libGLES_mali.so` en
    Helio G99).

Opción de driver externo en Mali: PanVK (faux123 v1.1.6, zenithblue 26.3.1)
importable como zip, como en NFSMW y xendroid-mali.

## Cómo se mide (nada de "se siente fluido")

- Contador de fps + tiempo por frame: el overlay de depuración del SDK
  (`src/ui/overlay/debug_overlay.cpp`, `Guest: %.1f FPS`), que solo se abre
  con la tecla F3 (`bind_debug_overlay`, `src/ui/rex_app.cpp`). En el
  teléfono no hay teclado y el mando virtual no lo abre, así que la medida
  de fps en el teléfono necesita otra vía (o un teclado USB/BT): hoy no hay
  contador visible durante el juego en el teléfono.
- Prueba de referencia: jugar el primer capítulo completo midiendo fps
  mínimo, medio y picos; el mínimo manda, no la media.
- Aceptación: **60 fps sostenidos en gameplay en el teléfono del usuario**,
  y 60 fps en Adreno (matriz de comunidad: Redmi 10C, POCO X6 Pro,
  Galaxy A56). Si un dispositivo no llega a 60, baja a 540p a mano
   (diálogo de gráficos, 960×540) antes de bajar a 30 fps: no hay bajada
     automática.
