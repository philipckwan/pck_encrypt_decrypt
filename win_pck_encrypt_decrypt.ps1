#
# win_pck_encrypt_decrypt.ps1
# Author: philipckwan@gmail.com
#

#$encode_extension="b64e";
#$decode_extension="b64d";

#$args1=$args[0];

$ARG_KEY_ENCRYPT_IN_MEMORY="enc";
$ARG_KEY_DECRYPT_IN_MEMORY="dec";
$ARG_KEY_ENCRYPT_IN_FILE="encf";
$ARG_KEY_DECRYPT_IN_FILE="decf";
$ARG_KEY_DECRYPT_IN_FILE_STRIP_EXTENSION="decfs";
$ARG_KEY_ENCRYPT_FROM_STDIN="enci";
$ARG_KEY_DECRYPT_FROM_STDIN="deci";
$ARG_KEY_DECRYPT_FROM_STDIN_SHOW_B64_CHARSET="decis";
$ARG_KEY_DECRYPT_FROM_STDIN_COPY_TO_CLIPBOARD="decic";

$global:arg_filepath="";
$global:arg_base64_option="";
$global:arg_tag_key="";

$MODE_FILE="FILE";
$MODE_TAG="TAG";
$MODE_STDIN="STDIN";
$global:mode=$MODE_STDIN;

$global:filename=""
$global:filepath=""
$tag_key_head=""
$tag_key_tail=""

$global:password_from_stdin=""
$global:password_processed=""
$global:password_reversed=""
$global:password_hash=New-Object system.collections.hashtable
$result_filename_suffix=""
#$global:is_process_whole_file=$false;
$global:is_generate_results_in_file=$false;
$global:is_encrypt=$false;
$global:is_strip_extension=$false
$global:is_show_b64_charset=$false
$global:is_copy_to_clipboard=$false
$global:tag_keys=@();
$global:encrypted_from_stdin=""

$SALT_SEPARATOR="-"
$SALT_LENGTH=3
$global:is_salt_used=$false
$global:salt_num_repeat=0
$global:salt_shuffle_idx=0
$MULTI_ENCRYPT_LENGTH=4
$global:is_multi_encrypt_used=$false
$global:encrypt_decrypt_rounds=2

$base64_charset="/+9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
$password_valid_charset="9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

function print_usage_and_exit {
    write-host ""
    write-host "win_pck_encrypt_decrypt.ps1: v0.4"
    write-host ""
    write-host "Usage: win_pck_encrypt_decrypt.ps1 <filepath> <encrypt option> [<tag key>]"
	write-host "-filepath: relative path and filename"
	write-host "-encrypt option: enc | dec | encf | decf"
	write-host "-tag key: < and > will be added to enclose tag key; i.e. pck-01 becomes <pck-01> and </pck-01>"
	write-host " it is expected the tag is enlosed like xml tags, i.e. <pck-01> and </pck-01> enclosed the inline text to be encrypted"
	write-host " if <tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted"
	write-host ""
	exit 1
}

function command_check {
    write-host "command_check: TBC for this windows version"
}

function commands_check {
    write-host "commands_check: TBC for this windows version"
}

function arguments_check($commandLineArgs) {
    $firstFourCharArg1=$commandLineArgs[0].substring(0,4);
    if ((-Not (Test-Path $commandLineArgs[0])) -and (($ARG_KEY_DECRYPT_FROM_STDIN -eq $firstFourCharArg1) -or ($ARG_KEY_ENCRYPT_FROM_STDIN -eq $firstFourCharArg1))) {
        #write-host "arguments_check: enci or deci mode;"
        $global:arg_base64_option=$commandLineArgs[0];
        $last_char=$arg_base64_option.substring($arg_base64_option.length - 1, 1);
        if ($last_char -match '^\d+$') {
            $global:encrypt_decrypt_rounds=$last_char
            $global:arg_base64_option=$arg_base64_option.substring(0, $arg_base64_option.length - 1);
        }
        #write-host "__global:encrypt_decrypt_rounds:$($global:encrypt_decrypt_rounds); arg_base64_option:$($arg_base64_option);"
        $global:mode=$MODE_STDIN;
        #write-host "__mode:$($mode);";
        if ($ARG_KEY_ENCRYPT_FROM_STDIN -eq $arg_base64_option) {
            $global:is_encrypt=$true;
        } elseif ($ARG_KEY_DECRYPT_FROM_STDIN -eq $arg_base64_option) {
            $global:is_encrypt=$false;
        } elseif ($ARG_KEY_DECRYPT_FROM_STDIN_SHOW_B64_CHARSET -eq $arg_base64_option) {
            $global:is_encrypt=$false;
            $global:is_show_b64_charset=$true
        } elseif ($ARG_KEY_DECRYPT_FROM_STDIN_COPY_TO_CLIPBOARD -eq $arg_base64_option) {
            $global:is_encrypt=$false;
            $global:is_copy_to_clipboard=$true
        } else {
            write-host "arguments_check: ERROR - arg_base64_option is not specified correctly"
            print_usage_and_exit;
        }
        write-host "arguments_check: mode: [$mode]"
        write-host "arguments_check: is_encrypt: [$is_encrypt]"
        write-host "arguments_check: is_show_b64_charset: [$is_show_b64_charset]"
        write-host "arguments_check: is_copy_to_clipboard: [$is_copy_to_clipboard]"
        
        if ($is_encrypt -eq $true) {
            write-host "arguments_check: encrypt_decrypt_roundds: [$encrypt_decrypt_rounds]"
        }
    } else {
        $global:arg_filepath=$commandLineArgs[0];
        $global:arg_base64_option=$commandLineArgs[1];
        $last_char=$arg_base64_option.substring($arg_base64_option.length - 1, 1);
        if ($last_char -match '^\d+$') {
            $global:encrypt_decrypt_rounds=$last_char
            $global:arg_base64_option=$arg_base64_option.substring(0, $arg_base64_option.length - 1);
        }
        $global:arg_tag_key=$commandLineArgs[2]

        if (($null -eq $arg_filepath) -or ($null -eq $arg_base64_option)) {
            write-host "arguments_check: ERROR - not all arguments are specified"
            print_usage_and_exit;
        }
    
        if ($ARG_KEY_ENCRYPT_IN_MEMORY -eq $arg_base64_option) {
            $global:is_encrypt=$true;
        } elseif ($ARG_KEY_DECRYPT_IN_MEMORY -eq $arg_base64_option) {
            $global:is_encrypt=$false;
        } elseif ($ARG_KEY_ENCRYPT_IN_FILE -eq $arg_base64_option) {
            $global:is_generate_results_in_file=$true;
            $global:is_encrypt=$true;
        } elseif ($ARG_KEY_DECRYPT_IN_FILE -eq $arg_base64_option) {
            $global:is_generate_results_in_file=$true;
            $global:is_encrypt=$false;
        } elseif ($ARG_KEY_DECRYPT_IN_FILE_STRIP_EXTENSION -eq $arg_base64_option) {
            $global:is_generate_results_in_file=$true;
            $global:is_encrypt=$false;
            $global:is_strip_extension=$true;
        } else {
            write-host "arguments_check: ERROR - arg_base64_option is not specified correctly: $($arg_base64_option);";
            print_usage_and_exit
        }
        if (Test-Path $arg_filepath -PathType Leaf) {
            $global:filepath=(Get-Item $arg_filepath ).DirectoryName;
            $global:filename=(Get-Item $arg_filepath ).Name;
        } elseif (Test-Path $arg_filepath) {
            $global:filepath=(Get-Item $arg_filepath ).FullName;
            $global:filename=$null;
        } else {
            write-host "arguments_check: ERROR - [$($arg_filepath)] is not a valid file or directory";
            print_usage_and_exit;
        } 
        
        if ($null -eq $arg_tag_key) {
            $global:mode=$MODE_FILE
        } else {
            $global:mode=$MODE_TAG
            $global:tag_keys = $arg_tag_key.Split(",");
        }
        write-host "arguments_check: arg_filepath: [$arg_filepath]"
		write-host "arguments_check: is_encrypt: [$is_encrypt]"
		write-host "arguments_check: mode: [$mode]"
		write-host "arguments_check: filepath: [$filepath]"
		write-host "arguments_check: filename: [$filename]"
        if ($is_encrypt -eq $true) {
            write-host "arguments_check: encrypt_decrypt_rounds: [$encrypt_decrypt_rounds]"
        }
        if (($is_generate_results_in_file -eq $false) -and ($mode -eq $MODE_FILE)) {
            write-host "arguments_check: ERROR - encryption and decryption for a whole file in memory is currently not supported" 
            exit 1
        }
    }
}

function ask_password {
    $password_confirm_from_stdin=""
    $password_from_stdin_secure = Read-Host 'Please enter the password' -AsSecureString
    $global:password_from_stdin = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_from_stdin_secure));
    if ($password_from_stdin.length -lt 3) {
        write-host "ERROR - password must be at least 3 characters long."
        exit 1
    }
    for ($i=0; $i -lt $password_from_stdin.length; $i++) {
        $aPasswordChar=$password_from_stdin.substring($i, 1);
        if (-Not $password_valid_charset.contains($aPasswordChar)) {
            write-host "ERROR - password contains invalid character(s)."
			write-host "Please only input alphanumeric characters for password."
			exit 1
        }
    }
    if ($is_encrypt -eq $true) {
        $password_confirm_from_stdin_secure = Read-Host 'Please re-enter the password' -AsSecureString
        $password_confirm_from_stdin = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_confirm_from_stdin_secure));
        if ($password_from_stdin -cne $password_confirm_from_stdin) {
            write-host "ERROR - password entered do not match.";
            Exit 1;
        }
    }
}

function extract_salt_from_encrypted_text($text) {
    if ($text.substring(2,1) -eq "$SALT_SEPARATOR") {
        $global:is_salt_used=$true
        $global:salt_num_repeat=$text.substring(0,1);
        $global:salt_shuffle_idx=$text.substring(1,1);
        $encrypt_decrypt_rounds=1
    } elseif ($text.substring(3,1) -eq "$SALT_SEPARATOR") {
        $global:is_multi_encrypt_used=$true
        $global:salt_num_repeat=$text.substring(0,1);
        $global:salt_shuffle_idx=$text.substring(1,1);
        $global:encrypt_decrypt_rounds=$text.substring(2,1);
    } else {
        $encrypt_decrypt_rounds=1
        #write-host "extract_salt_from_encrypted_text: salt is not found"
    }
}

function password_process {
    # if encrypt and tag based
	#  generate $salt_num_repeat and $salt_shuffle_idx,then apply to $password_processed and $password_reversed
	# if decrypt and tag based
	#  take from $salt_num_repeat and $salt_shuffle_idx, then apply to $password_processed and $password_reversed
	# if not tag based (i.e. whole file encrypt/decrypt)
	#  salt is not supported for this type
    $combined_password_base64_charset="$($password_from_stdin)$($base64_charset)"
    $global:password_processed=""    
    for ($i=0; $i -lt $combined_password_base64_charset.length; $i++) {
        $thisChar=$combined_password_base64_charset.substring($i, 1)
        if (-Not $global:password_processed.contains($thisChar)) {
            $global:password_processed="$($global:password_processed)$($thisChar)"
        }
    }

    if ($is_encrypt -eq $true) {
        # the first salt is the number of times to repeat, $salt_num_repeat
        $global:salt_num_repeat=get-random -min 1 -max 10

        # the second salt is the index to shuffle from the end, $salt_shuffle_idx
        $global:salt_shuffle_idx=get-random -min 1 -max 10
    } 

    #write-host "__password_processed START:[$($password_processed)]; $salt_num_repeat; $salt_shuffle_idx;"
    if ($salt_num_repeat -gt 0) {
        #$salt_shuffle_idx_neg=$salt_shuffle_idx*-1;
        for ($i = 0; $i -lt $salt_num_repeat; $i++) {
            $pwd_salt=$password_processed.substring($password_processed.length-$salt_shuffle_idx);
            $pwd_salt = $pwd_salt[$pwd_salt.length..0] -join ""
            #write-host "__pwd_salt:[$($pwd_salt)]"
            $global:password_processed="$($pwd_salt)$($password_processed.substring(0, $password_processed.length-$salt_shuffle_idx))"
            #write-host "__password_processed:[$($password_processed)]"
        }
        #write-host "__password_processed END:[$password_processed]"
    }

    $global:password_reversed=$global:password_processed[$global:password_processed.Length..0] -join ""

    # in windows, we have to use a hash table to shuffle the base64 char, because windows doesn't have the 'tr' command
    for ($i=0; $i -lt $password_processed.length; $i++) {
        $password_processed_char=$password_processed.substring($i, 1)
        $password_reversed_char=$password_reversed.substring($i, 1)
        $global:password_hash[$password_processed_char] = $password_reversed_char
    }
    # have to add extra mapping to the hashmap for characters like '='
    $global:password_hash['='] = '='
}

function do_work_on_stdin {
    $global:encrypted_from_stdin = Read-Host "Please type or paste the encrypted text: "
    ask_password;
    if ($is_encrypt -eq $false) {
        extract_salt_from_encrypted_text($encrypted_from_stdin);
        if ($is_salt_used -eq $true) {
            $global:encrypted_from_stdin=$encrypted_from_stdin.substring($SALT_LENGTH);
        } elseif ($is_multi_encrypt_used -eq $true) {
            $global:encrypted_from_stdin=$encrypted_from_stdin.substring($MULTI_ENCRYPT_LENGTH);
        }
        write-host "__salt_num_repeat:$($salt_num_repeat); salt_shuffle_idx:$($salt_shuffle_idx); encrypt_decrypt_rounds:$($encrypt_decrypt_rounds);"
    }
    password_process;
    $results=$encrypted_from_stdin;
    if ($is_encrypt -eq $false) {
        for ($i=0; $i -lt $encrypt_decrypt_rounds; $i++) {
            #write-host "__loop[$($i)];"
            $b64DecSB = [System.Text.StringBuilder]::new()
            for ($j = 0; $j -lt $results.length; $j++) {
                [void]$b64DecSB.append($password_hash["$($results[$j])"])
            }
            $results = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b64DecSB.ToString())) 2>$null
            if ([string]::IsNullOrEmpty($results)) {
                write-host "ERROR - result is empty, you might have entered a wrong password"
                exit 1
            }
        }
    } else {
        for ($i=0; $i -lt $encrypt_decrypt_rounds; $i++) {
            $results_bytes = [System.Text.Encoding]::ASCII.GetBytes($results)
            $results_b64=[Convert]::ToBase64String($results_bytes);
            $b64EncSB = [System.Text.StringBuilder]::new()
            for ($j = 0; $j -lt $results_b64.length; $j++) {
                [void]$b64EncSB.append($password_hash["$($results_b64[$j])"])
            }
            $results = $b64EncSB.ToString();
        }
        $results = "$salt_num_repeat" + "$salt_shuffle_idx" + "$encrypt_decrypt_rounds" + $SALT_SEPARATOR + $results
    }
    if ($is_show_b64_charset -eq $true) {
        write-host "password_processed: [$password_processed]"
        write-host "password_reversed:  [$password_reversed]"
    }
    if ($is_copy_to_clipboard -eq $true) {
        Set-Clipboard -Value $results
        write-host ""
        write-host "The decrypted text is already copied to clipboard"
        write-host ""
    } else {
        write-host "$results"
    }
}

function do_work {
    <#
    write-host "do_work: filepath:[$($filepath)];";
    write-host "do_work: filename:[$($filename)];";
    write-host "do_work: password_from_stdin:[$($password_from_stdin)];"
    write-host "do_work: is_process_whole_file:[$($is_process_whole_file)];"
    write-host "do_work: is_encrypt:[$($is_encrypt)];"
    write-host "do_work: is_generate_results_in_file:[$($is_generate_results_in_file)];"
    #>
    Push-Location $filepath
    [Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
    if ($null -eq $filename) {
        write-host "do_work: filename is not defined, directory based"
        $files = Get-ChildItem .
        for($i=0; $i -lt $files.Length; $i++) {
            do_work_on_a_file($files[$i])
        }
    } else {
        write-host "do_work: filename is defined, specific file based"
        do_work_on_a_file($filename)
    }
    [void](Pop-Location)

}

function do_work_on_a_file($f) {
    $fB64="$($f).b64e"
    $g="$($f).$($arg_base64_option)"
    $matched_text=""
    $result=""
    $results_with_tags=""
    $matched_found=$false

    if ($is_generate_results_in_file -eq $true) {
        write-host "do_work_on_a_file: will generate a file from: [$f] to:[$g]"
        [void](New-Item $g)
    }

    if ($is_process_whole_file -eq $true) {
        password_process
        if ($is_generate_results_in_file -eq $false -and $is_encrypt -eq $true) {
            $by = [char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($f));
            [IO.File]::WriteAllBytes($fB64, $by)
            $b64Tmp = [IO.File]::ReadAllText($fB64);
            $b64EncSB = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $b64Tmp.length; $i++) {
                [void]$b64EncSB.append($password_hash["$($b64Tmp[$i])"])
            }
            write-host $b64EncSB.ToString()
        } elseif ($is_generate_results_in_file -eq $true -and $is_encrypt -eq $true) {
            $by = [char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($f));
            [IO.File]::WriteAllBytes($fB64, $by)
            $b64Tmp = [IO.File]::ReadAllText($fB64);
            $b64EncSB = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $b64Tmp.length; $i++) {
                [void]$b64EncSB.append($password_hash["$($b64Tmp[$i])"])
            }
            [IO.File]::WriteAllText($g, $b64EncSB.ToString())
        } elseif ($is_generate_results_in_file -eq $false -and $is_encrypt -eq $false) {
            $encTmp = [IO.File]::ReadAllText($f)
            $b64DecSB = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $encTmp.length; $i++) {
                [void]$b64DecSB.append($password_hash["$($encTmp[$i])"])
            }
            [IO.File]::WriteAllText($fB64, $b64DecSB.ToString())
            $b64Txt = [char[]][IO.File]::ReadAllBytes($fB64);
            $text = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b64Txt))
            write-host $text
        } elseif ($is_generate_results_in_file -eq $true -and $is_encrypt -eq $false) {
            $encTmp = [IO.File]::ReadAllText($f)
            $b64DecSB = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $encTmp.length; $i++) {
                [void]$b64DecSB.append($password_hash["$($encTmp[$i])"])
            }
            [IO.File]::WriteAllText($fB64, $b64DecSB.ToString())
            $b64Txt = [char[]][IO.File]::ReadAllBytes($fB64);
            $by = [Convert]::FromBase64String($b64Txt);
            [IO.File]::WriteAllBytes($g,$by);
        } 
    } else {
        [System.IO.File]::ReadLines($f) | ForEach-Object {
            $tag_found=$false
            for($i=0; $i -lt $tag_keys.Length; $i++) {
                $tag_key_head = "<$($tag_keys[$i])>"
                $tag_key_tail = "</$($tag_keys[$i])>"
                $tag_key_head_matched_idx = $_.indexof($tag_key_head);
                if ($tag_key_head_matched_idx -ge 0) {
                    $text_before_matched = $_.substring(0, $tag_key_head_matched_idx)
                    $tag_key_tail_matched_idx = $_.lastindexof($tag_key_tail);
                    if ($tag_key_tail_matched_idx -gt $tag_key_head_matched_idx) {
                        $text_after_matched = $_.substring($tag_key_tail_matched_idx + $tag_key_tail.Length);
                        $tag_found=$true
                        $matched_found=$true
                        $matched_text = $_.substring($tag_key_head_matched_idx + $tag_key_head.length, $tag_key_tail_matched_idx - ($tag_key_head_matched_idx + $tag_key_head.length));

                        if ($is_encrypt -eq $false) {
                            extract_salt_from_encrypted_text($matched_text)
                            if ($is_salt_used -eq $true) {
                                $matched_text=$matched_text.substring($global:SALT_LENGTH)
                            }
                        } 

                        password_process

                        #write-host "__matched_text:[$matched_text]";
                        #write-host "__password_processed:[$global:password_processed]"
                        #write-host "__password_reversed: [$global:password_reversed]"
                        #write-host "__salt_num_repeat:[$global:salt_num_repeat]"
                        #write-host "__salt_shuffle_idx:[$global:salt_shuffle_idx]"
                        if ($is_encrypt -eq $true) {
                            $matched_text_bytes = [System.Text.Encoding]::ASCII.GetBytes($matched_text)
                            $matched_text_b64=[Convert]::ToBase64String($matched_text_bytes);
                            $b64EncSB = [System.Text.StringBuilder]::new()
                            $b64EncSB.append("$salt_num_repeat$salt_shuffle_idx$SALT_SEPARATOR")
                            for ($j = 0; $j -lt $matched_text_b64.length; $j++) {
                                [void]$b64EncSB.append($password_hash["$($matched_text_b64[$j])"])
                            }
                            $results = $b64EncSB.ToString();
                            #write-host "__results:[$results]"
                        } else {
                            $b64DecSB = [System.Text.StringBuilder]::new()
                            for ($i = 0; $i -lt $matched_text.length; $i++) {
                                [void]$b64DecSB.append($password_hash["$($matched_text[$i])"])
                            }
                            $results = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b64DecSB.ToString()))
                            #write-host "__decrypted: results:[$results]"
                        }
                        $results_with_tags="$tag_key_head$results$tag_key_tail"

                        if ($is_generate_results_in_file -eq $true) {
                            "$text_before_matched$results_with_tags$text_after_matched" >> $g
                        } else {
                            write-host "RESULTS: [$results_with_tags]"
                        }
                    }
                }
                #write-host "[$($tag_keys[$i])];"
                
            }
            if ($tag_found -eq $false) {
                if ($is_generate_results_in_file -eq $true) {
                    "$_" >> $g
                }
            }
        }
        if ($matched_found -eq $false) {
            write-host "WARN: No matched text is found."
        }
    }
}

arguments_check($args);
if ($mode -eq $MODE_STDIN) {
    do_work_on_stdin;
} else {
    do_work_on_filepath;
}
#ask_password;
#do_work;
exit 0;