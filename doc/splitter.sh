#!/bin/bash

# Usage: ./fast_split.sh input.txt

if [ $# -ne 1 ]; then
  echo "Usage: $0 input_file"
  exit 1
fi

input_file="$1"
max_chars=100000
output_prefix="split/${input_file%.*}_part"
counter=1
offset=0

file_size=$(wc -c < "$input_file")
echo "File size: $file_size characters"

while [ $offset -lt $file_size ]; do
  output_file="${output_prefix}_${counter}.md"
  dd if="$input_file" of="$output_file.tmp" bs=1 count=$max_chars skip=$offset status=none
  echo '```' >> "$output_file"  
  cat "$output_file.tmp" >> "$output_file"
  echo '```' >> "$output_file"
  rm -f "$output_file.tmp"
  echo "Created $output_file"
  offset=$((offset + max_chars))
  counter=$((counter + 1))
done
