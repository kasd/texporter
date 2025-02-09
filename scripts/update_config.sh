#!/bin/bash

set -e  # Exit on any error

JSON_FILE="config.json"  # Path to your JSON file

# URLs for YouTube ranges
CIDR4_URL="https://raw.githubusercontent.com/touhidurrr/iplist-youtube/refs/heads/main/cidr4.txt"
CIDR6_URL="https://raw.githubusercontent.com/touhidurrr/iplist-youtube/refs/heads/main/cidr6.txt"

# AWS IP ranges
AWS_IP_RANGES_URL="https://ip-ranges.amazonaws.com/ip-ranges.json"

# Google IP ranges
GOOGLE_IP_RANGES_URL="https://www.gstatic.com/ipranges/goog.json"
CLOUD_IP_RANGES_URL="https://www.gstatic.com/ipranges/cloud.json"

# Zoom IP ranges
ZOOM_URLS=(
    "https://assets.zoom.us/docs/ipranges/Zoom.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomMeetings.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomMeetings-IPv6.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomCRC.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomPhone.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomPhone-IPv6.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomCC.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomCC-IPv6.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomCDN.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomCDN-IPv6.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomApps.txt"
    "https://assets.zoom.us/docs/ipranges/ZoomApps-IPv6.txt"
)

# Create temp files
TMP_CIDR4=$(mktemp)
TMP_CIDR6=$(mktemp)
TMP_AWS=$(mktemp)
TMP_GOOGLE=$(mktemp)
TMP_CLOUD=$(mktemp)
TMP_ZOOM=$(mktemp)

# Function to cleanup temp files on exit
cleanup() {
    rm -f "$TMP_CIDR4" "$TMP_CIDR6" "$TMP_AWS" "$TMP_GOOGLE" "$TMP_CLOUD" "$TMP_ZOOM"
}
trap cleanup EXIT

# Download CIDR lists
curl -s "$CIDR4_URL" -o "$TMP_CIDR4"
curl -s "$CIDR6_URL" -o "$TMP_CIDR6"
curl -s "$AWS_IP_RANGES_URL" -o "$TMP_AWS"
curl -s "$GOOGLE_IP_RANGES_URL" -o "$TMP_GOOGLE"
curl -s "$CLOUD_IP_RANGES_URL" -o "$TMP_CLOUD"

# Download Zoom IP ranges
for url in "${ZOOM_URLS[@]}"; do
    curl -s "$url" >> "$TMP_ZOOM"
    echo "" >> "$TMP_ZOOM"  # Ensure newline between files
done

# Convert YouTube lists to JSON arrays
CIDR4_JSON=$(jq -R -s -c 'split("\n") | map(select(length > 0))' "$TMP_CIDR4")
CIDR6_JSON=$(jq -R -s -c 'split("\n") | map(select(length > 0))' "$TMP_CIDR6")

# Extract AWS IPv4 and IPv6 prefixes
AWS_IPV4_JSON=$(jq -c '[.prefixes[] | select(.service == "AMAZON") | .ip_prefix]' "$TMP_AWS")
AWS_IPV6_JSON=$(jq -c '[.ipv6_prefixes[] | select(.service == "AMAZON") | .ipv6_prefix]' "$TMP_AWS")

# Extract Google IPv4 and IPv6 prefixes
GOOGLE_IPV4_JSON=$(jq -c '[.prefixes[] | .ipv4Prefix // empty]' "$TMP_GOOGLE")
GOOGLE_IPV6_JSON=$(jq -c '[.prefixes[] | .ipv6Prefix // empty]' "$TMP_GOOGLE")
CLOUD_IPV4_JSON=$(jq -c '[.prefixes[] | .ipv4Prefix // empty]' "$TMP_CLOUD")
CLOUD_IPV6_JSON=$(jq -c '[.prefixes[] | .ipv6Prefix // empty]' "$TMP_CLOUD")

# Merge Google and Cloud prefixes
TMP_GOOGLE_IPV4=$(mktemp)
TMP_GOOGLE_IPV6=$(mktemp)

echo "$GOOGLE_IPV4_JSON" > "$TMP_GOOGLE_IPV4"
echo "$CLOUD_IPV4_JSON" >> "$TMP_GOOGLE_IPV4"
GOOGLE_FINAL_IPV4=$(jq -c -s 'add | map(select(. != null))' "$TMP_GOOGLE_IPV4")

echo "$GOOGLE_IPV6_JSON" > "$TMP_GOOGLE_IPV6"
echo "$CLOUD_IPV6_JSON" >> "$TMP_GOOGLE_IPV6"
GOOGLE_FINAL_IPV6=$(jq -c -s 'add | map(select(. != null))' "$TMP_GOOGLE_IPV6")

# Process Zoom IPs
ZOOM_IPV4_JSON=$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+' "$TMP_ZOOM" | jq -R -s -c 'split("\n") | map(select(length > 0))')
ZOOM_IPV6_JSON=$(grep -E '^[0-9a-fA-F:]+\/[0-9]+' "$TMP_ZOOM" | jq -R -s -c 'split("\n") | map(select(length > 0))')

# Update the JSON file
jq --argjson ipv4 "$CIDR4_JSON" --argjson ipv6 "$CIDR6_JSON" \
   --argjson aws_ipv4 "$AWS_IPV4_JSON" --argjson aws_ipv6 "$AWS_IPV6_JSON" \
   --argjson google_ipv4 "$GOOGLE_FINAL_IPV4" --argjson google_ipv6 "$GOOGLE_FINAL_IPV6" \
   --argjson zoom_ipv4 "$ZOOM_IPV4_JSON" --argjson zoom_ipv6 "$ZOOM_IPV6_JSON" \
   'map(
       if .name == "youtube" then 
           .ipv4 = $ipv4 | .ipv6 = $ipv6 
       elif .name == "amazon" then 
           .ipv4 = $aws_ipv4 | .ipv6 = $aws_ipv6 
       elif .name == "google" then 
           .ipv4 = $google_ipv4 | .ipv6 = $google_ipv6 
       elif .name == "zoom" then 
           .ipv4 = $zoom_ipv4 | .ipv6 = $zoom_ipv6 
       else . 
       end
   )' "$JSON_FILE" > "$JSON_FILE.tmp" && mv "$JSON_FILE.tmp" "$JSON_FILE"

echo "JSON file updated successfully."

