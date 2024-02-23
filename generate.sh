#! /bin/bash

# inputs
regions=("us-east-1" "eu-west-1" "ap-southeast-1")
resources="*"
excludes="identitystore"

# Check if Terraformer is installed
if ! command -v terraformer &> /dev/null
then
    echo "Terraformer is not installed. Proceeding with installation..."
    version=$(curl -s https://api.github.com/repos/GoogleCloudPlatform/terraformer/releases/latest | grep tag_name | cut -d '"' -f 4); 
    curl -LO "https://github.com/GoogleCloudPlatform/terraformer/releases/download/$version/terraformer-aws-linux-amd64"
    chmod +x terraformer-aws-linux-amd64
    sudo mv terraformer-aws-linux-amd64 /usr/local/bin/terraformer
else
    echo "Terraformer is already installed."
fi
terraformer --version

# run terraformer import
mkdir -p generated
cd generated
cat << EOF > terraform.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.31.0"
    }
  }
}
EOF

terraform init -no-color
for region in "${regions[@]}"; do
  terraformer import aws --regions "$region" --resources "$resources" --path-pattern "{output}/{provider}/$region/{service}" --excludes "$excludes" --profile=""
done

# remove empty tf directories: those that contain only provider.tf, variables.tf, and *.tfstate
generated_dir="generated"
if [ -d "$generated_dir" ]; then
  tf_dirs=$(find ./ -type f -name "provider.tf" -exec dirname {} \; | sort -u)
  for dir in $tf_dirs; do
    if [[ -z $(find "$dir" -type f ! \( -name "provider.tf" -o -name "variables.tf" -o -name "*.tfstate" \)) ]]; then
      rm -r "$dir"
    else 
      rm ${dir}/*.tfstate
    fi
  done
fi

# first-level secret redaction
cat << EOF > config.yaml
detectors:
  - name: certificate authority
    keywords:
      - CERTIFICATE
    regex:
      adjective: -----BEGIN CERTIFICATE-----
  - name: AWS API key ID
    keywords:
      - AKIA
    regex:
      adjective: (?i)AKIA[0-9A-Z]{16}
  - name: userbase64 attribute
    keywords:
      - user_data
    regex:
      adjective: \buser_data.*
EOF

printf "\*.tfstate\n.terraform*" > exclude.txt
docker run --rm -v "$PWD:/path" trufflesecurity/trufflehog:latest filesystem /path/generated --exclude-paths=/path/exclude.txt --config=/path/config.yaml  --json > output01.json

# redact secrets identified
if [ -e "output01.json" ]; then
  while IFS= read -r line; do
    file_name="$(echo "$line" | jq -r '.SourceMetadata.Data.Filesystem.file' | sed 's|^/path/||')"
    if [ "$(echo "$line" | jq -r '.ExtraData.name')" = "certificate authority" ]; then
      line_number="$(echo "$line" | jq -r '.SourceMetadata.Data.Filesystem.line')"
      sed -i "${line_number}s/.*/# <redacted>/" "${file_name}"
    else 
      to_redact="$(echo "$line" | jq -r '.Raw | gsub("/"; "\\/")')"
      find "${file_name}" -type f -exec sed -i "s/${to_redact}/# <redacted>/g" {} \;
    fi
  done < "output01.json"
fi

# run trufflehog again to check
docker run --rm -v "$PWD:/path" trufflesecurity/trufflehog:latest filesystem /path/generated --exclude-paths=/path/exclude.txt --config=/path/config.yaml  --json > output02.json

if [ -s output02.json ]; then
  jq . output02.json
  echo "verify the secrets detected!"
else 
  rm output02.json
  echo "detection and redaction via trufflehog have completed."
fi

# cleanup
rm -r .terraform*
rm config.yaml
rm exclude.txt
rm output01.json