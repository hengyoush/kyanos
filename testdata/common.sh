#!/usr/bin/env bash
function check_patterns_not_in_file() {  
    local file_path=$1  
    local pattern=$2  
  
    if grep -q "$pattern" "$file_path"; then  
        echo "Pattern '$pattern' found in file '$file_path'." >&2  
        exit 1  
    fi  
}  
function check_patterns_in_file() {  
    local file_path=$1  
    local pattern=$2  
  
    if  ! grep -q "$pattern" "$file_path"; then  
        echo "Pattern '$pattern' not found in file '$file_path'." >&2  
        exit 1  
    fi  
}  

function check_time_detail_completed() {
    filename=$1
    check_patterns_not_in_file "$filename" '\-0\.000'  
    check_patterns_not_in_file "$filename" '1970\-01' 
    check_patterns_not_in_file "$filename" 'count]=0' 
}