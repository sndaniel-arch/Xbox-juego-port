#!/bin/bash
# Start a Gradle 8.14 daemon MANUALLY as a direct child of this shell.
# WHY: daemons forked by the Gradle launcher get their TCP intercepted by the
# runtime (fake-accept: connect() "succeeds" but no bytes ever reach the peer,
# so dependency downloads fail with "Connection reset"). A daemon started
# directly by us may keep real networking. If the client still forks its own
# daemon, this one is ignored (check with `gradle --status`).
# Log: daemon-manual.log in this dir. Stop: pkill -f GradleDaemon (bracket trick).
set -euo pipefail  # (Ronda 5, auditor F — R5-F12.) Antes solo -u: un java que no arranca dejaba el script en 0.
# (Ronda 8, auditor F — R8-F10.) El truststore iba con ruta absoluta
# /home/hatch/workspace/... (solo funciona en esta VM) mientras el resto
# del script ya usa $HOME; derivarlo del directorio del script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GRADLE_HOME="$HOME/workspace/tools/gradle-8.14"
JAVA_HOME="$HOME/workspace/tools/jdk-17"
export GRADLE_USER_HOME="$HOME/.gradle"
export JAVA_HOME
[ -x "$JAVA_HOME/bin/java" ] || { echo "java no encontrado en $JAVA_HOME/bin/java"; exit 1; }
cd "$(dirname "$0")"
nohup "$JAVA_HOME/bin/java" \
  --add-opens=java.base/java.lang=ALL-UNNAMED \
  --add-opens=java.base/java.lang.invoke=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  --add-opens=java.prefs/java.util.prefs=ALL-UNNAMED \
  --add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED \
  --add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED \
  --add-opens=java.base/java.nio.charset=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED \
  --add-opens=java.xml/javax.xml.namespace=ALL-UNNAMED \
  -XX:MaxMetaspaceSize=256m \
  -Xmx1024m \
  -Dfile.encoding=UTF-8 \
  -Djava.net.preferIPv4Stack=true \
  -Djavax.net.ssl.trustStore="$SCRIPT_DIR/mitm-truststore.jks" \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -Duser.country=US -Duser.language=en -Duser.variant \
  -cp "$GRADLE_HOME/lib/gradle-daemon-main-8.14.jar" \
  -javaagent:"$GRADLE_HOME/lib/agents/gradle-instrumentation-agent-8.14.jar" \
  org.gradle.launcher.daemon.bootstrap.GradleDaemon 8.14 \
  > daemon-manual.log 2>&1 &
DAEMON_PID=$!
# (Ronda 6, auditor F — R6-F12.) Igual que run.sh: set -e no cubre el
# trabajo en segundo plano y el script anunciaba el pid aunque java muriese
# al instante (jar ausente, JAVA_HOME roto). Comprobar que sigue vivo.
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null || { echo "manual daemon no arranco (ver daemon-manual.log)"; exit 1; }
echo "manual daemon pid $DAEMON_PID"
