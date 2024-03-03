#!/bin/bash

#
# pck_encrypt_decrypt.sh
# Author: philipckwan@gmail.com
#

BASE64=base64
BASENAME=basename
DIRNAME=dirname
TR=tr
REV=rev
READ=read
PBCOPY=pbcopy

ARG_KEY_ENCRYPT_IN_MEMORY="enc"
ARG_KEY_DECRYPT_IN_MEMORY="dec"
ARG_KEY_DECRYPT_IN_MEMORY_COPY_TO_CLIPBOARD="decc"
ARG_KEY_ENCRYPT_IN_FILE="encf"
ARG_KEY_DECRYPT_IN_FILE="decf"
ARG_KEY_DECRYPT_IN_FILE_STRIP_EXTENSION="decfs"
ARG_KEY_ENCRYPT_FROM_STDIN="enci"
ARG_KEY_DECRYPT_FROM_STDIN="deci"
ARG_KEY_DECRYPT_FROM_STDIN_SHOW_B64_CHARSET="decis"
ARG_KEY_DECRYPT_FROM_STDIN_COPY_TO_CLIPBOARD="decic"

arg_filepath=""
arg_base64_option=""
arg_encrypt_decrypt_rounds="not set"
arg_tag_key=""

MODE_FILE="FILE"
MODE_TAG="TAG"
MODE_STDIN="STDIN"
mode=$MODE_STDIN

filename=""
filepath=""
tag_key_head=""
tag_key_tail=""

password_from_stdin=""
password_processed=""
password_reversed=""
result_filename_suffix=""
is_generate_results_in_file=false
is_encrypt=false
is_strip_extension=false
is_show_b64_charset=false
is_copy_to_clipboard=false
tag_keys=()
encrypted_from_stdin=""

# used by do_work_one_line, decrypt_one_line, encrypt_one_line
input_one_line=""
output_one_line=""
error_one_line=""

# header_version
# 1 - v1, oldest version, no header
# 2 - v2, is_salt_used, length == 2, e.g. 23-xxx
# 3 - v3, is_multi_encrypt_used, length == 3, e.g. 362-xxx
# 4 - v4, is_text_shuffle_used, length == 4, e.g. 4551-xxx
header_version=1
SALT_SEPARATOR="-"
HEADER_V2_LENGTH=3
salt_num_repeat=0
salt_shuffle_idx=0
HEADER_V3_LENGTH=4
encrypt_decrypt_rounds=2
HEADER_V4_LENGTH=5
text_shuffle_version_supported=1
text_shuffle_charset_processed=""
text_shuffle_charset_reversed=""
matchedIdx=0

base64_charset="/+9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
password_valid_charset="9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
text_shuffle_charset="0123456789 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

function print_usage_and_exit {
	echo ""
	echo "pck_encrypt_decrypt.sh v1.13.1"
	echo ""
	echo "Usage 1: pck_encrypt_decrypt.sh <filepath> <encrypt option> [<tag key>]"
	echo "-filepath: relative path and filename"
	echo "-encrypt option: enc | dec | encf | decf | decc | decfs"
	echo "-tag key: < and > will be added to enclose tag key; i.e. pck-01 becomes <pck-01> and </pck-01>"
	echo " it is expected the tag is enlosed like xml tags, i.e. <pck-01> and </pck-01> enclosed the inline text to be encrypted"
	echo " if <tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted"
	echo ""
	echo "Usage 2: pck_encrypt_decrypt.sh enci|deci"
	echo "-encrypt and decrypt by promoting (reading from stdin)"
	echo ""
	echo "For encryption, you may optionally provide the number of rounds of encryption to be done, ranges from 1 to 9"
	echo "The more rounds of encryption is set, the more difficult it is to be decrypted"
	echo "e.g."
	echo "$ pck_encrypt_decrypt.sh enci5"
	echo "The above will run the encryption with 5 rounds"
	exit 1
}

function command_check {
	which $1 > /dev/null 2>&1
	if [ 1 -eq $? ]
	then
		echo "command_check: ERROR - command [$1] not found"
		print_usage_and_exit
	fi
}

function commands_check_post_arguments {
	which "${PBCOPY}" > /dev/null 2>&1
	if [ 1 -eq $? ] && [ "${is_copy_to_clipboard}" = true ]
	then
		echo "commands_check_post_arguments: ERROR - command [$PBCOPY] not found and the chosen mode requires copy to clipboard"
		print_usage_and_exit
	fi
} 

function commands_check {
	command_check "${BASE64}"
	command_check "${BASENAME}"
	command_check "${DIRNAME}"
	command_check "${TR}"
	command_check "${REV}"
	command_check "${READ}"
	#command_check "${PBCOPY}"
}

function arguments_check {
	firstFourCharArg1=${1:0:4}
	if [[ ! -f $1 && ! -d $1 && ( "$ARG_KEY_DECRYPT_FROM_STDIN" == "$firstFourCharArg1" || "$ARG_KEY_ENCRYPT_FROM_STDIN" == "$firstFourCharArg1" ) ]]
	#if [ "$ARG_KEY_DECRYPT_FROM_STDIN" == "$1" ] || [ "$ARG_KEY_ENCRYPT_FROM_STDIN" == "$1" ] || [ "$ARG_KEY_DECRYPT_FROM_STDIN_SHOW_B64_CHARSET" == "$1" ] || [ "$ARG_KEY_DECRYPT_FROM_STDIN_COPY_TO_CLIPBOARD" == "$1" ] 
	then
		arg_base64_option=$1
		last_char=${arg_base64_option:0-1}
		if [ "$last_char" -eq "$last_char" ] 2>/dev/null; then
			encrypt_decrypt_rounds=$last_char
			arg_base64_option=${arg_base64_option%?}
		fi
		mode=$MODE_STDIN
		if [ "$ARG_KEY_ENCRYPT_FROM_STDIN" == "$arg_base64_option" ]
		then
			is_encrypt=true	
		elif [ "$ARG_KEY_DECRYPT_FROM_STDIN" == "$arg_base64_option" ]
		then
			is_encrypt=false
		elif [ "$ARG_KEY_DECRYPT_FROM_STDIN_SHOW_B64_CHARSET" == "$arg_base64_option" ]
		then
			is_encrypt=false
			is_show_b64_charset=true
		elif [ "$ARG_KEY_DECRYPT_FROM_STDIN_COPY_TO_CLIPBOARD" == "$arg_base64_option" ]
		then
			is_encrypt=false
			is_copy_to_clipboard=true
		else
			echo "arguments_check: ERROR - arg_base64_option is not specified correctly"
			print_usage_and_exit
		fi

		echo "arguments_check: mode: [$mode]"
		echo "arguments_check: is_encrypt: [$is_encrypt]"
		echo "arguments_check: is_show_b64_charset: [$is_show_b64_charset]"
		echo "arguments_check: is_copy_to_clipboard: [$is_copy_to_clipboard]"
		
		if [ "${is_encrypt}" == true ] ; then
			echo "arguments_check: encrypt_decrypt_rounds: [$encrypt_decrypt_rounds]"
		fi
	else
		arg_filepath=$1
		arg_base64_option=$2
		last_char=${arg_base64_option:0-1}
		if [ "$last_char" -eq "$last_char" ] 2>/dev/null; then
			encrypt_decrypt_rounds=$last_char
			arg_base64_option=${arg_base64_option%?}
		fi
		arg_tag_key=$3
		if [ -z "$arg_filepath" ] || [ -z "$arg_base64_option" ]
		then
			echo "arguments_check: ERROR - not all arguments are specified"
			print_usage_and_exit
		fi

		if [ "$ARG_KEY_ENCRYPT_IN_MEMORY" == "$arg_base64_option" ]
		then
			is_encrypt=true
		elif [ "$ARG_KEY_DECRYPT_IN_MEMORY" == "$arg_base64_option" ]
		then
			is_encrypt=false
		elif [ "$ARG_KEY_DECRYPT_IN_MEMORY_COPY_TO_CLIPBOARD" == "$arg_base64_option" ]
		then
			is_encrypt=false
			is_copy_to_clipboard=true
		elif [ "$ARG_KEY_ENCRYPT_IN_FILE" == "$arg_base64_option" ]
		then
			is_generate_results_in_file=true
			is_encrypt=true
		elif [ "$ARG_KEY_DECRYPT_IN_FILE" == "$arg_base64_option" ]
		then
			is_generate_results_in_file=true
			is_encrypt=false
		elif [ "$ARG_KEY_DECRYPT_IN_FILE_STRIP_EXTENSION" == "$arg_base64_option" ]
		then
			is_generate_results_in_file=true
			is_encrypt=false
			is_strip_extension=true
		else
			echo "arguments_check: ERROR - arg_base64_option is not specified correctly"
			print_usage_and_exit
		fi
		
		if [ -f $arg_filepath ]
		then
			filepath=`${DIRNAME} ${arg_filepath}`
			filename=`${BASENAME} ${arg_filepath}`
		elif [ -d $arg_filepath ]
		then
			filepath=${arg_filepath}
			filename=""
		else
			echo "arguments_check: ERROR - [$arg_filepath] is not a valid file or directory"
			print_usage_and_exit
		fi

		if  [ -z "$arg_tag_key" ]
		then
			mode=$MODE_FILE			
		else 
			mode=$MODE_TAG
			tag_keys=(${arg_tag_key//,/ })
		fi
		echo "arguments_check: arg_filepath: [$arg_filepath]"
		echo "arguments_check: is_encrypt: [$is_encrypt]"
		echo "arguments_check: is_copy_to_clipboard: [$is_copy_to_clipboard]"
		echo "arguments_check: mode: [$mode]"
		echo "arguments_check: filepath: [$filepath]"
		echo "arguments_check: filename: [$filename]"
		if [ "${is_encrypt}" == true ] ; then
			echo "arguments_check: encrypt_decrypt_rounds: [$encrypt_decrypt_rounds]"
		fi

		if [[ "${is_generate_results_in_file}" == false && "${mode}" = "${MODE_FILE}" ]] ; then
				echo "arguments_check: ERROR - encryption and decryption for a whole file in memory is currently not supported"
				exit 1
		fi
	fi
}

function ask_password {
	password_confirm_from_stdin=""
	${READ} -sp "Please enter the password: " password_from_stdin
	echo ""
	if [[ ${#password_from_stdin} -lt 3 ]] ; then
		echo "ERROR - password must be at least 3 characters long."
		exit 1
	fi
	for (( i=0; i<${#password_from_stdin}; i++ )); do
		aPasswordChar="${password_from_stdin:$i:1}"
		stringIndexOf $password_valid_charset $aPasswordChar
		if [[ $matchedIdx -lt 0 ]]
		then
			echo "ERROR - password contains invalid character(s)."
			echo "Please only input alphanumeric characters for password."
			exit 1
		fi
	done
	if [ "${is_encrypt}" = true ]
	then
		${READ} -sp "Please re-enter the password: " password_confirm_from_stdin
		echo ""
		if [[ "$password_from_stdin" != "$password_confirm_from_stdin" ]]
		then
			echo "ERROR - password entered do not match."
			exit 1
		fi	
	fi
}

function extract_header_from_encrypted_text {
	text=$1
	if [ "${text:2:1}" == "$SALT_SEPARATOR" ] ; then
		header_version=2
		salt_num_repeat=${text:0:1}
		salt_shuffle_idx=${text:1:1}
		encrypt_decrypt_rounds=1
	elif [ "${text:3:1}" == "$SALT_SEPARATOR" ] ; then
		header_version=3
		salt_num_repeat=${text:0:1}
		salt_shuffle_idx=${text:1:1}
		encrypt_decrypt_rounds=${text:2:1}
	elif [ "${text:4:1}" == "$SALT_SEPARATOR" ] ; then
		header_version=4
		salt_num_repeat=${text:0:1}
		salt_shuffle_idx=${text:1:1}
		encrypt_decrypt_rounds=${text:2:1}
		text_shuffle_version=${text:3:1}
		if [ "${text_shuffle_version}" -ne "${text_shuffle_version_supported}" ] ; then
			echo "ERROR - invalid text_shuffle_version [${text_shuffle_version}]";
			exit 1
		fi
	else
		echo "extract_header_from_encrypted_text: header is not found"
		encrypt_decrypt_rounds=1
	fi
	#echo "extract_header_from_encrypted_text: header_version: [${header_version}]"
}

function password_process {
	# obtain the password_removed_dups, dup_char_array and dup_count_array
	# dup_char_array and dup_count_array are for text shuffle
	password_removed_dups=""
	dup_char_array=()
	dup_count_array=()

	for (( i=0; i<${#password_from_stdin}; i++ )); do
    thisChar="${password_from_stdin:$i:1}"
    if [[ $password_removed_dups != *${thisChar}* ]]
    then
      password_removed_dups="${password_removed_dups}${thisChar}"
    else
			dup_char_array+=("${thisChar}")
      dup_count_array+=($i)
    fi
  done
	#echo "password_process: password_removed_dups:[${password_removed_dups}]"
	#for i in ${!dup_char_array[@]}; do
  #  echo "__element $i in dup_char_array [${dup_char_array[$i]}]"
  #  echo "__element $i in dup_count_array [${dup_count_array[$i]}]"
  #done

	text_shuffle_charset_processed="${text_shuffle_charset}"

  for i in ${!dup_char_array[@]}; do
    thisLetter="${dup_char_array[$i]}"
    thisNumber="${dup_count_array[$i]}"
    #echo "__i:[$i]; charset:[${text_shuffle_charset_processed}]; thisLetter:[${thisLetter}]; thisNumber:[${thisNumber}]"
    combined_charset="${thisLetter}${text_shuffle_charset_processed}"
    charset_processed=""
    for (( j=0; j<${#combined_charset}; j++ )); do
      thisChar="${combined_charset:$j:1}"
      if [[ $charset_processed != *${thisChar}* ]]
      then
        charset_processed="${charset_processed}${thisChar}"
      fi
    done
    thisNumber_idx_neg=$(($thisNumber*-1))
    charset_move_to_head=`echo ${charset_processed:$thisNumber_idx_neg}`
    head_length=$((${#charset_processed}+${thisNumber_idx_neg}))
    charset_tail=${charset_processed:0:${head_length}}
    charset_processed="${charset_move_to_head}${charset_tail}"
    text_shuffle_charset_processed="${charset_processed}"
  done
	text_shuffle_charset_reversed=`echo ${text_shuffle_charset_processed} | $REV`
  #echo "password_process: text_shuffle_charset_processed: [${text_shuffle_charset_processed}]" 
	#echo "password_process: text_shuffle_charset_reversed:  [$text_shuffle_charset_reversed]"

	# if encrypt and tag based
	#  generate $salt_num_repeat and $salt_shuffle_idx,then apply to $password_processed and $password_reversed
	# if decrypt and tag based
	#  take from $salt_num_repeat and $salt_shuffle_idx, then apply to $password_processed and $password_reversed
	# if not tag based (i.e. whole file encrypt/decrypt)
	#  salt is not supported for this type
	combined_password_base64_charset="${password_removed_dups}${base64_charset}"
	password_processed=""
	for (( i=0; i<${#combined_password_base64_charset}; i++ )); do
		thisChar="${combined_password_base64_charset:$i:1}"
		if [[ $password_processed != *${thisChar}* ]]
		then
			password_processed="${password_processed}${thisChar}"
		fi
	done

	if [ "${is_encrypt}" = true ] ; then
		# the first salt is the number of times to repeat, $salt_num_repeat
		salt_num_repeat=$(($RANDOM%9+1))

		# the second salt is the index to shuffle from the end, $salt_shuffle_idx
		salt_shuffle_idx=$(($RANDOM%9+1))
	fi
	
	if [ ${salt_num_repeat} -gt 0 ] ; then
		salt_shuffle_idx_neg=$(($salt_shuffle_idx*-1))
		for (( i=0; i<${salt_num_repeat}; i++ )); do			
			pwd_salt=`echo ${password_processed:$salt_shuffle_idx_neg} | $REV`
			head_length=$((${#password_processed}+${salt_shuffle_idx_neg}))
			pwd_head=${password_processed:0:${head_length}}
			password_processed="${pwd_salt}${pwd_head}"
		done
	fi
	#fi
	password_reversed=`echo ${password_processed} | $REV`
}

function encrypt_one_line {
	error_one_line=""

	password_process
	output_one_line="${input_one_line}"
	# first, perform the text shuffle
	#echo "encrypt_one_line: text_shuffle_charset_processed:[$text_shuffle_charset_processed]"
	#echo "encrypt_one_line: text_shuffle_charset_reversed: [$text_shuffle_charset_reversed]"
	output_one_line=`echo "${output_one_line}" | $TR "${text_shuffle_charset_processed}" "${text_shuffle_charset_reversed}"`

	for (( i=0; i<${encrypt_decrypt_rounds}; i++ )); do
		output_one_line=`echo "${output_one_line}" | ${BASE64} | $TR "${password_processed}" "${password_reversed}"`
	done
	output_one_line="${salt_num_repeat}${salt_shuffle_idx}${encrypt_decrypt_rounds}${text_shuffle_version_supported}${SALT_SEPARATOR}${output_one_line}"
}

function decrypt_one_line {
	extract_header_from_encrypted_text "${input_one_line}"
	input_one_line_header_stripped=""
	error_one_line=""
	if [ ${header_version} -eq 2 ] ; then
		input_one_line_header_stripped=${input_one_line:${HEADER_V2_LENGTH}}
	elif [ ${header_version} -eq 3 ] ; then
		input_one_line_header_stripped=${input_one_line:${HEADER_V3_LENGTH}}
	elif [ ${header_version} -eq 4 ] ; then
		input_one_line_header_stripped=${input_one_line:${HEADER_V4_LENGTH}}								
	fi
	#echo "decrypt_one_line: input_one_line_header_stripped:[${input_one_line_header_stripped}]"
	password_process
	output_one_line="${input_one_line_header_stripped}"
	for (( i=0; i<${encrypt_decrypt_rounds}; i++ )); do
		output_one_line=`echo "${output_one_line}" | $TR "${password_processed}" "${password_reversed}" 2> /dev/null | ${BASE64} --decode 2> /dev/null`
	done
	if [ -z "${output_one_line}" ]  ; then
		error_one_line="ERROR - result is empty, you might have entered a wrong password"
	else
		# apply the text shuffle if header_version == 4
		if [ ${header_version} -eq 4 ] ; then
			if [ ${text_shuffle_version_supported} -eq 1 ] ; then
				#echo "decrypt_one_line: text_shuffle_charset_processed:[$text_shuffle_charset_processed]"
				#echo "decrypt_one_line: text_shuffle_charset_reversed: [$text_shuffle_charset_reversed]"
				output_one_line=`echo "${output_one_line}" | $TR "${text_shuffle_charset_processed}" "${text_shuffle_charset_reversed}"`
			else 
				echo  "ERROR - invalid text_shuffle_version_supported: [${text_shuffle_version_supported}]"
				exit 1
			fi
		fi 
	fi
}

function do_work_on_stdin {
	if [ "${is_encrypt}" = false ] ; then
		${READ} -r -p "Please type or paste the encrypted text: " encrypted_from_stdin
	else
		${READ} -r -p "Please type or paste the text to be encrypted: " encrypted_from_stdin
	fi
	
	ask_password
	input_one_line="${encrypted_from_stdin}"
	if [ "${is_encrypt}" = false ] ; then
		decrypt_one_line
		if [ ! -z "${error_one_line}" ] ; then
			echo "${error_one_line}"
			exit 1
		fi
	else
		encrypt_one_line
	fi

	if [ "${is_show_b64_charset}" = true ] ; then
		echo "password_processed: [$password_processed]"
		echo "password_reversed:  [$password_reversed]"
	fi
	if [ "${is_copy_to_clipboard}" = true ] ; then
		echo "$output_one_line" | ${PBCOPY}
		echo ""
		echo "The decrypted text is already copied to clipboard; length of text:${#output_one_line};"
		echo ""
	else
		echo "$output_one_line"
	fi
}

function do_work_on_filepath {
	ask_password
	cd $filepath
	if [ -z "$filename" ]
	then
		echo "do_work: filename is not defined, directory based"
		shopt -s nullglob
		for f in *; do		
			do_work_on_a_file $f
		done
	else
		echo "do_work: filename is defined, specific file based"
		f=$filename
		do_work_on_a_file $f
	fi
}

function do_work_on_a_file {
	f=$1
	f_tmp1="${f}.1.tmp"
	f_tmp2="${f}.2.tmp"
	f_tmpPH=""
	if [ "${is_strip_extension}" = true ] ; then
		g="${f%.*}"
	else
		g="${f}.${arg_base64_option}"
	fi
	matched_text=""
	results=""
	results_with_tags=""
	matched_found=false

	if [ "${is_generate_results_in_file}" = true ] ; then
		echo "do_work_on_a_file: will generate a file from: [$f] to:[$g]"
		echo -n > $g
	fi

	if [ "${mode}" = "${MODE_FILE}" ]
	then
		# assume $is_generate_results_in_file is always true here
		if [[ "${is_encrypt}" = true ]] ; then
			password_process
			cat $f > $f_tmp1
			for (( i=0; i<${encrypt_decrypt_rounds}; i++ )); do
				cat $f_tmp1 | ${BASE64} | $TR "${password_processed}" "${password_reversed}" > $f_tmp2
				f_tmpPH=$f_tmp1
				f_tmp1=$f_tmp2
				f_tmp2=$f_tmpPH
			done
			echo "${salt_num_repeat}${salt_shuffle_idx}${encrypt_decrypt_rounds}${SALT_SEPARATOR}" > $g
			cat $f_tmp1 >> $g
		else
			read -r firstline < $f
			extract_header_from_encrypted_text "${firstline}"
			password_process
			if [ ${header_version} -ge 3 ] ; then
				tail -n +2 "$f" > "$f_tmp1"
			else
				cat $f > $f_tmp1
			fi
			for (( i=0; i<${encrypt_decrypt_rounds}; i++ )); do
				cat $f_tmp1 | $TR "${password_processed}" "${password_reversed}" 2> /dev/null | ${BASE64} --decode 2> /dev/null > $f_tmp2
				f_tmpPH=$f_tmp1
				f_tmp1=$f_tmp2
				f_tmp2=$f_tmpPH
			done
			cat $f_tmp1 > $g
		fi	
		rm -rf $f_tmp1 
		rm -rf $f_tmp2
	else
		# $mode must be MODE_TAG here
		echo "-----RESULTS START-----"
		while IFS= read -r line || [ -n "$line" ];
		do
			tag_found=false
			for tag_key in "${tag_keys[@]}"
			do
				tag_key_head="<${tag_key}>"
            	tag_key_tail="</${tag_key}>"
				stringIndexOf "$line" "$tag_key_head"
				tag_key_head_matched_idx=$matchedIdx
				#echo "__line:[$line]; tag_key_head_matched_idx:[$tag_key_head_matched_idx];"
				if [ ${tag_key_head_matched_idx} -ge 0 ]
				then
					text_before_matched=${line:0:$tag_key_head_matched_idx}
					stringIndexOf "$line" "$tag_key_tail"
					tag_key_tail_matched_idx=$matchedIdx
					if [ ${tag_key_tail_matched_idx} -gt ${tag_key_head_matched_idx} ]
					then
						text_after_matched=${line:$tag_key_tail_matched_idx + ${#tag_key_tail}}
						tag_found=true
						matched_found=true
						echo ""
						echo "Found this line:"
						echo "$line"
						matched_text=${line:$tag_key_head_matched_idx+${#tag_key_head}:$tag_key_tail_matched_idx-($tag_key_head_matched_idx+${#tag_key_head})}
						input_one_line="${matched_text}"
						if [ "${is_encrypt}" = false ] ; then
							decrypt_one_line
							if [ ! -z "${error_one_line}" ] ; then
								echo "${error_one_line}"
							elif [ "${is_copy_to_clipboard}" = true ] ; then
								echo "$output_one_line" | ${PBCOPY}
								echo "DECRYPTED: The decrypted text is already copied to clipboard; length of text:${#output_one_line};"
								echo "Warning: only the first matched tag will be decrypted and copied to clipboard"
								echo "-----RESULTS END-----"
								exit 0
							fi							
						else
							encrypt_one_line
						fi
						results_with_tags="${tag_key_head}${output_one_line}${tag_key_tail}"

						if [ "${is_generate_results_in_file}" = true ] ; then
							echo "$text_before_matched$results_with_tags$text_after_matched" >> $g
						else
							echo "DECRYPTED: The decrypted line is:"
							echo "$text_before_matched$results_with_tags$text_after_matched"
						fi
						break						
					fi
				fi
			done
			if [ "${tag_found}" = false ] ; then
				if [ "${is_generate_results_in_file}" = true ] ; then
					echo "$line" >> $g
				fi
			fi
		done < $f
		if [ "${matched_found}" = false ] ; then
			echo "WARN: No matched text is found."
		fi
		echo ""
		echo "-----RESULTS END-----"	
	fi
}

function stringIndexOf {
    #set matchedIdx with  the index of a text matched with a string, -1 if not found
    text=$1
    match=$2
    local text_before_matched=${text%%$match*}
    local text_after_matched=${text##*$match}
    local text_len=${#text}
    local text_before_matched_len=${#text_before_matched}
    local text_after_matched_len=${#text_after_matched}
    if (($text_len == $text_before_matched_len && $text_len == $text_after_matched_len))
    then
        # match not found
        #echo "stringIndexOf: match not found"
        matchedIdx=-1
    else
        matchedIdx=$text_before_matched_len
        matched_text=
    fi   
}

commands_check
arguments_check $@
commands_check_post_arguments
if [ "${mode}" = "${MODE_STDIN}" ]
then
	do_work_on_stdin
else
	do_work_on_filepath
fi
#ask_password
#do_work
exit 0

