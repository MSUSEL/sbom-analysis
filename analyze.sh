cd -- "$(dirname "$0")" >/dev/null || exit 1 2>&1

# Check if there is a provided image
if [ $# -ne 1 ]; then
  echo "No argument supplied"
  echo "Usage: analyze.sh <image>"
  exit 1
fi

res="$(docker manifest inspect "$1" 2>/dev/null)"
if [[ $res == "" ]]; then
  echo "Image doesn't exist"
  exit 1
fi

function join_by {
  local IFS="$1"
  shift
  echo "$*"
}

OIFS=$IFS
IFS='/:'
spo_array=($1)
IFS=$OIFS
path="cache/$(join_by / ${spo_array[*]})"
mkdir -p "$path"

grype "$1" --output json >"$path/grype.json"
grype "$1" --output sarif >"$path/grype.sarif.json"
syft "$1" --output json >"$path/syft.json"
trivy image -f sarif -o "$path/trivy.sarif.json" --security-checks vuln "$1"
trivy image -f cyclonedx -o "$path/trivy.cyclonedx.json" --security-checks vuln "$1"
trivy image -f spdx -o "$path/trivy.spdx.json" --security-checks vuln "$1"
trivy image -f json -o "$path/trivy.json" --security-checks vuln "$1"
