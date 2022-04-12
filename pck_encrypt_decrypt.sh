#!/bin/bash

#
# pck_encrypt_decrypt.sh
# v1.4
# Author: philipckwan@gmail.com
#
# This is an encryption and decryption tool based on some common Linux commands, run in bash script.
# For a full explanation of this tool, should refer to the author's github.
# Some quick highlight of this tool:
# -it can encrypt and decrypt a whole binary file, in any format. The results is base64 text
# -it can encrypt and decrypt a segment of a plaintext file. The key is to enclose such text in xml like element as an identifier
# -the results of the encryption and decryption can be outputted in the terminal, thus only in memory. 
#  Or it can be outputted into a file, thus persisted into the filesystem.
# -the encryption and decryption technology is based on base64 encoding and followed by a text shuffling,
#  based on a passphrase setup by the user upon encryption
#

BASE64=base64
BASENAME=basename
DIRNAME=dirname
TR=tr
REV=rev
READ=read

arg_filepath=$1
arg_base64_option=$2
arg_tag_key=$3
command_base64_with_argument=""

ARG_KEY_ENCRYPT_IN_MEMORY="enc"
ARG_KEY_DECRYPT_IN_MEMORY="dec"
ARG_KEY_ENCRYPT_IN_FILE="encf"
ARG_KEY_DECRYPT_IN_FILE="decf"

filename=""
filepath=""
tag_key_head=""
tag_key_tail=""

password_from_stdin=""
password_processed=""
password_reversed=""
result_filename_suffix=""
is_process_whole_file=false
is_generate_results_in_file=false
is_encrypt=false

base64_charset="/+9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

function print_usage_and_exit {
	echo ""
	echo "Usage: pck_encrypt_decrypt.sh <filepath> <encrypt option> [<tag key>]"
	echo "-filepath: relative path and filename"
	echo "-encrypt option: enc | dec | encf | decf"
	echo "-tag key: < and > will be added to enclose tag key; i.e. pck-01 becomes <pck-01> and </pck-01>"
	echo " it is expected the tag is enlosed like xml tags, i.e. <pck-01> and </pck-01> enclosed the inline text to be encrypted"
	echo " if <tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted"
	echo ""
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

function commands_check {
    command_check "${BASE64}"
	command_check "${BASENAME}"
	command_check "${DIRNAME}"
	command_check "${TR}"
	command_check "${REV}"
	command_check "${READ}"
}

function arguments_check {
	if [ -z "$arg_filepath" ] || [ -z "$arg_base64_option" ]
	then
		echo "arguments_check: ERROR - not all arguments are specified"
		print_usage_and_exit
	fi

	if [ "$ARG_KEY_ENCRYPT_IN_MEMORY" == "$arg_base64_option" ]
	then
		command_base64_with_argument="${BASE64}"
		is_generate_results_in_file=false
		is_encrypt=true
	elif [ "$ARG_KEY_DECRYPT_IN_MEMORY" == "$arg_base64_option" ]
	then
		command_base64_with_argument="${BASE64} --decode"
		is_generate_results_in_file=false
		is_encrypt=false
	elif [ "$ARG_KEY_ENCRYPT_IN_FILE" == "$arg_base64_option" ]
	then
		command_base64_with_argument="${BASE64}"
		is_generate_results_in_file=true
		is_encrypt=true
	elif [ "$ARG_KEY_DECRYPT_IN_FILE" == "$arg_base64_option" ]
	then
		command_base64_with_argument="${BASE64} --decode"
		is_generate_results_in_file=true
		is_encrypt=false
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
	
	echo "arguments_check: arg_filepath: [$arg_filepath]"
	echo "arguments_check: arg_base64_option: [$arg_base64_option]"
	echo "arguments_check: filepath: [$filepath]"
	echo "arguments_check: filename: [$filename]"

	if  [ -z "$arg_tag_key" ]
	then
		is_process_whole_file=true
		echo "arguments_check: is_process_whole_file=true"
	else 
		is_process_whole_file=false
		tag_key_head="<${arg_tag_key}>"
		tag_key_tail="</${arg_tag_key}>"
		echo "arguments_check: tag key pair: [$tag_key_head],[$tag_key_tail]"
	fi
	
}

function ask_password {
	password_confirm_from_stdin=""
	${READ} -sp "Please enter the password: " password_from_stdin
	echo ""
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
	#echo "password_from_stdin: [$password_from_stdin]"
	#echo "password_confirm_from_stdin: [$password_confirm_from_stdin]"
}

function password_process {
	combined_password_base64_charset="${password_from_stdin}${base64_charset}"
	for (( i=0; i<${#combined_password_base64_charset}; i++ )); do
		thisChar="${combined_password_base64_charset:$i:1}"
		if [[ $password_processed == *${thisChar}* ]]
		then
			:
		else
			password_processed="${password_processed}${thisChar}"
		fi
	done
	password_reversed=`echo ${password_processed} | $REV`
	#echo "password_processed: [${password_processed}]"
	#echo "password_reversed:  [${password_reversed}]"
}

function do_work {
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
	g="${f}.${arg_base64_option}"
	matched_text=""
	results=""
	results_with_tags=""
	matched_found=false

	if [ "${is_generate_results_in_file}" = true ] ; then
		echo "do_work_on_a_file: will generate a file from: [$f] to:[$g]"
		echo -n > $g
	fi

	if [ "${is_process_whole_file}" = true ]
	then
		if [[ "${is_generate_results_in_file}" = false && "${is_encrypt}" = true ]] ; then
			cat $f | $command_base64_with_argument | $TR "${password_processed}" "${password_reversed}"
		elif [[ "${is_generate_results_in_file}" = true && "${is_encrypt}" = true ]] ; then
			cat $f | $command_base64_with_argument | $TR "${password_processed}" "${password_reversed}" > $g
		elif [[ "${is_generate_results_in_file}" = false && "${is_encrypt}" = false ]] ; then
			cat $f | $TR "${password_processed}" "${password_reversed}" | $command_base64_with_argument
		elif [[ "${is_generate_results_in_file}" = true && "${is_encrypt}" = false ]] ; then
			cat $f | $TR "${password_processed}" "${password_reversed}" | $command_base64_with_argument > $g
		fi	
	else
		while IFS= read -r line || [ -n "$line" ];
		do
			if [[ $line == ${tag_key_head}* && $line == *${tag_key_tail} ]]
			then
				#echo "do_work_on_a_file: line found: [$line]";
				matched_found=true
				tmp=${line#*${tag_key_head}}
				matched_text=${tmp%${tag_key_tail}*} 
				if [[ "${is_encrypt}" = true ]]
				then
					results=`echo "${matched_text}" | $command_base64_with_argument | $TR "${password_processed}" "${password_reversed}"`
				else
					results=`echo "${matched_text}" | $TR "${password_processed}" "${password_reversed}" | $command_base64_with_argument`
				fi
				results_with_tags="${tag_key_head}${results}${tag_key_tail}"
				
				if [[ "${is_generate_results_in_file}" = true ]] ; then
					echo "$results_with_tags" >> $g
				else
					echo "RESULTS: [$results_with_tags]"
				fi
			else
				if [[ "${is_generate_results_in_file}" = true ]] ; then
					echo "$line" >> $g
				fi
			fi
		done < $f
		if [ "$matched_found" = false ] ; then
			echo "WARN: No matched text is found."
		fi	
	fi


}

commands_check
arguments_check 
ask_password
password_process
do_work
exit 0

