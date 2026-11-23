#!/usr/bin/env bash
# Provision the supported launcher on an ephemeral GitHub-hosted Ubuntu runner only.
# Do not disable AppArmor, change sysctls, setuid a binary, or fall back to a host shell.
set -euo pipefail
install_package() {
  sudo apt-get -q update
  sudo env DEBIAN_FRONTEND=noninteractive apt-get -qy install --no-install-recommends "$1"
}
probe() {
  /usr/bin/bwrap --unshare-all --unshare-user --disable-userns --die-with-parent --new-session --cap-drop ALL \
    --clearenv --ro-bind /usr/bin /usr/bin --ro-bind /usr/lib /usr/lib --ro-bind-try /usr/lib64 /usr/lib64 \
    --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev \
    --dir /runtime --ro-bind-fd 3 /runtime/probe -- /runtime/probe 3</usr/bin/true
}
[[ -x /usr/bin/bwrap ]] || install_package bubblewrap
/usr/bin/bwrap --version
if ! probe; then
  # Noble may require an application-specific AppArmor userns policy. Use Ubuntu's
  # shipped *restricted* profile (its children cannot acquire capabilities). Never
  # replace an operator's existing profile or relax the machine-wide restriction.
  [[ ${RUNNER_ENVIRONMENT:-} == github-hosted && $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null) == 1 ]] || exit 1
  profile=/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
  [[ -f $profile ]] || install_package apparmor-profiles
  sudo apparmor_parser --add "$profile"
  probe
fi
