#!/usr/bin/env bash
set -euo pipefail
umask 077

git diff --quiet "$BASE" HEAD -- . \
    ':(exclude).github/workflows/graph594-snapshot-profile.yml' \
    ':(exclude)scripts/ci-profile-snapshot-cache.sh'
unset GH_TOKEN GITHUB_TOKEN

scratch=$(mktemp -d "${RUNNER_TEMP:?}/graph594-snapshot.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
cold="$scratch/cold"
restored="$scratch/restored"
archive="$scratch/compiler-cache.tar.zst"
mkdir "$cold" "$restored"
export GOCACHE="$cold"

printf 'Runner scratch occupancy before snapshot:\n'
df -PB1 "$scratch"
go version
goreleaser check

started=$SECONDS
go mod download
printf 'MODULE_DOWNLOAD_SECONDS=%s\n' "$(( SECONDS - started ))"

release_snapshot() {
    local label=$1 started=$SECONDS
    goreleaser release --snapshot --clean --skip=publish,sign,sbom -p 2
    printf '%s_SNAPSHOT_SECONDS=%s\n' "$label" "$(( SECONDS - started ))"
    (
        shopt -s nullglob
        cd dist
        archives=(*.tar.gz *.zip)
        sums=(*_SHA256SUMS)
        [[ ${#archives[@]} == 5 && ${#sums[@]} == 1 ]]
        for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
            matches=(graph2otel_*_"$target".tar.gz)
            [[ ${#matches[@]} == 1 ]]
        done
        matches=(graph2otel_*_windows_amd64.zip)
        [[ ${#matches[@]} == 1 ]]
        sha256sum --check -- "${sums[0]}"
        sha256sum -- "${archives[@]}" "${sums[0]}" > "$scratch/$label.sha256"
    )
}

release_snapshot COLD
raw_bytes=$(du -sb -- "$cold" | cut -f1)
printf 'RAW_CACHE_BYTES=%s\n' "$raw_bytes"
df -PB1 "$scratch"
if (( raw_bytes > 3000000000 )); then
    echo 'PROFILE_HELD=raw compiler cache exceeds the 3 GB entry budget'
    exit 78
fi

started=$SECONDS
tar --posix -C "$cold" -cf - . | zstd -q -T2 -o "$archive"
printf 'CACHE_PACK_SECONDS=%s\n' "$(( SECONDS - started ))"
archive_bytes=$(stat --format=%s "$archive")
printf 'CACHE_TRANSPORT_BYTES=%s\n' "$archive_bytes"
if (( archive_bytes > 3000000000 )); then
    echo 'PROFILE_HELD=compressed cache exceeds the 3 GB entry budget'
    exit 78
fi

rm -rf -- "$cold"
started=$SECONDS
zstd -q -d -c "$archive" | tar -C "$restored" -xf -
printf 'CACHE_RESTORE_SECONDS=%s\n' "$(( SECONDS - started ))"
GOCACHE="$restored" release_snapshot RESTORED
if cmp -s "$scratch/COLD.sha256" "$scratch/RESTORED.sha256"; then
    echo 'ARCHIVE_DIGESTS_EQUAL=true'
else
    echo 'ARCHIVE_DIGESTS_EQUAL=false'
fi
echo 'PROFILE_COMPLETE=true'
