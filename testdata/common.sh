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
function check_patterns_not_in_file_with_last_lines() {  
    local file_path=$1  
    local pattern=$2  
    local last_lines=$3
  
    if tail -n $last_lines "$file_path" | grep -q "$pattern" ; then  
        echo "Pattern '$pattern' found in file '$file_path'  in last $last_lines lines." >&2  
        exit 1  
    fi  
}  

function check_patterns_in_file_with_last_lines() {  
    local file_path=$1  
    local pattern=$2  
    local last_lines=$3
  
    if  ! tail -n $last_lines "$file_path" | grep -q "$pattern"; then  
        echo "Pattern '$pattern' not found in file '$file_path' in last $last_lines lines." >&2  
        exit 1  
    fi  
}  


function check_time_detail_completed_with_last_lines() {
    filename=$1
    check_patterns_not_in_file_with_last_lines "$filename" '\-0\.000' $2 
    check_patterns_not_in_file_with_last_lines "$filename" '1970\-01' $2 
    check_patterns_not_in_file_with_last_lines "$filename" 'count]=0' $2 
}

function check_time_detail_completed() {
    filename=$1
    check_patterns_not_in_file "$filename" '\-0\.000'  
    check_patterns_not_in_file "$filename" '1970\-01' 
    check_patterns_not_in_file "$filename" 'count]=0' 
}