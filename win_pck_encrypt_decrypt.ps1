#
# win_pck_encrypt_decrypt.ps1
# Author: philipckwan@gmail.com
#

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
$global:is_generate_results_in_file=$false;
$global:is_encrypt=$false;
$global:is_strip_extension=$false
$global:is_show_b64_charset=$false
$global:is_copy_to_clipboard=$false
$global:tag_keys=@();
$global:encrypted_from_stdin=""

# used by decrypt_one_line, encrypt_one_line
$global:input_one_line=""
$global:output_one_line=""
$global:error_one_line=""

# header_version
# 1 - v1, oldest version, no header
# 2 - v2, is_salt_used, length == 2, e.g. 23-xxx
# 3 - v3, is_multi_encrypt_used, length == 3, e.g. 362-xxx
# 4 - v4, is_text_shuffle_used, length == 4, e.g. 4551-xxx
$global:header_version=1
$SALT_SEPARATOR="-"
$HEADER_V2_LENGTH=3
$global:salt_num_repeat=0
$global:salt_shuffle_idx=0
$HEADER_V3_LENGTH=4
$global:encrypt_decrypt_rounds=2
$HEADER_V4_LENGTH=5
$text_shuffle_version_supported=1
$global:text_shuffle_charset_processed=""
$global:text_shuffle_charset_reversed=""
$global:text_shuffle_hash=New-Object system.collections.hashtable

$base64_charset="/+9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
$password_valid_charset="9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
$text_shuffle_charset="0123456789 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

function print_usage_and_exit {
    write-host ""
    write-host "win_pck_encrypt_decrypt.ps1: v2.11"
    write-host ""
    write-host "Usage: win_pck_encrypt_decrypt.ps1 <filepath> <encrypt option> [<tag key>]"
	write-host "-filepath: relative path and filename"
	write-host "-encrypt option: enc | dec | encf | decf"
	write-host "-tag key: < and > will be added to enclose tag key; i.e. pck-01 becomes <pck-01> and </pck-01>"
	write-host " it is expected the tag is enlosed like xml tags, i.e. <pck-01> and </pck-01> enclosed the inline text to be encrypted"
	write-host " if <tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted"
    write-host ""
	write-host "Usage 2: pck_encrypt_decrypt.ps1 enci|deci"
	write-host "-encrypt and decrypt by promoting (reading from stdin)"
	write-host ""
	write-host "For encryption, you may optionally provide the number of rounds of encryption to be done, ranges from 1 to 9"
	write-host "The more rounds of encryption is set, the more difficult it is to be decrypted"
	write-host "e.g."
	write-host "$ pck_encrypt_decrypt.ps1 enci5"
	write-host "The above will run the encryption with 5 rounds"
	exit 1
}

function command_check {
    write-host "command_check: TBC for this windows version"
}

function commands_check {
    write-host "commands_check: TBC for this windows version"
}

function arguments_check($commandLineArgs) {
    if ($null -eq $commandLineArgs[0]) {
        write-host "arguments_check: ERROR - no arguments provided, will print the help page;"
        print_usage_and_exit;
    }
    $firstFourCharArg1=$commandLineArgs[0].substring(0,4);
    if ((-Not (Test-Path $commandLineArgs[0])) -and (($ARG_KEY_DECRYPT_FROM_STDIN -eq $firstFourCharArg1) -or ($ARG_KEY_ENCRYPT_FROM_STDIN -eq $firstFourCharArg1))) {
        $global:arg_base64_option=$commandLineArgs[0];
        $last_char=$arg_base64_option.substring($arg_base64_option.length - 1, 1);
        if ($last_char -match '^\d+$') {
            $global:encrypt_decrypt_rounds=$last_char
            $global:arg_base64_option=$arg_base64_option.substring(0, $arg_base64_option.length - 1);
        }
        $global:mode=$MODE_STDIN;
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
            write-host "arguments_check: encrypt_decrypt_rounds: [$encrypt_decrypt_rounds]"
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

function extract_header_from_encrypted_text($text) {
    if ($text.substring(2,1) -eq "$SALT_SEPARATOR") {
        $global:header_version=2
        $global:salt_num_repeat=$text.substring(0,1);
        $global:salt_shuffle_idx=$text.substring(1,1);
        $global:encrypt_decrypt_rounds=1
    } elseif ($text.substring(3,1) -eq "$SALT_SEPARATOR") {
        $global:header_version=3
        $global:salt_num_repeat=$text.substring(0,1);
        $global:salt_shuffle_idx=$text.substring(1,1);
        $global:encrypt_decrypt_rounds=$text.substring(2,1);
    } elseif ($text.substring(4,1) -eq "$SALT_SEPARATOR") {
        $global:header_version=4
        $global:salt_num_repeat=$text.substring(0,1);
        $global:salt_shuffle_idx=$text.substring(1,1);
        $global:encrypt_decrypt_rounds=$text.substring(2,1);
        $global:text_shuffle_version=$text.substring(3,1);
        if ($text_shuffle_version -ne $text_shuffle_version_supported) {
            write-host "ERROR - invalid text_shuffle_version [$text_shuffle_version]";
            exit 1;
        }
    } else {
        write-host "extract_header_from_encrypted_text: header is not found"
        $global:encrypt_decrypt_rounds=1
    }
}

function password_process {
	# obtain the password_removed_dups, dup_char_array and dup_count_array
	# dup_char_array and dup_count_array are for text shuffle
    $password_removed_dups=""
    $dup_char_array = @()
    $dup_count_array = @()

    for ($i=0; $i -lt $password_from_stdin.length; $i++) {
        $thisChar=$password_from_stdin.substring($i, 1)
        if (-Not $password_removed_dups.contains($thisChar)) {
            $password_removed_dups="$($password_removed_dups)$($thisChar)"
        } else {
            $dup_char_array+=$thisChar
            $dup_count_array+=$i
        }
    }
    
    #write-host "password_process: password_removed_dups:[$password_removed_dups];"
    #for ($i=0; $i -lt $dup_char_array.length; $i++) {
    #    write-host "__element $i in dup_char_array [$($dup_char_array[$i])];"
    #    write-host "__element $i in dup_count_array [$($dup_count_array[$i])];"
    #}
    #exit 1
    $global:text_shuffle_charset_processed=$text_shuffle_charset

    for ($i=0; $i -lt $dup_char_array.length; $i++) {
        $thisLetter=$dup_char_array[$i]
        $thisNumber=$dup_count_array[$i]
        #write-host "__i:[$i]; charset:[$global:text_shuffle_charset_processed]; thisLetter:[$thisLetter]; thisNumber:[$thisNumber];"
        $combined_charset="$($thisLetter)$($global:text_shuffle_charset_processed)"
        $charset_processed=""
        for ($j=0; $j -lt $combined_charset.length; $j++) {
            $thisChar=$combined_charset.substring($j, 1)
            if (-Not $charset_processed.contains($thisChar)) {
                $charset_processed="$($charset_processed)$($thisChar)"
            }
        }
        $charset_move_to_head=$charset_processed.substring($charset_processed.length-$thisNumber);
        $global:text_shuffle_charset_processed="$($charset_move_to_head)$($charset_processed.substring(0, $charset_processed.length-$thisNumber))"
    }
    $global:text_shuffle_charset_reversed=$global:text_shuffle_charset_processed[$global:text_shuffle_charset_processed.Length..0] -join ""

    # in windows, we have to use a hash table to shuffle the text_shuffle char, because windows doesn't have the 'tr' command
    for ($i=0; $i -lt $text_shuffle_charset_processed.length; $i++) {
        $text_shuffle_processed_char=$text_shuffle_charset_processed.substring($i, 1)
        $text_shuffle_reversed_char=$text_shuffle_charset_reversed.substring($i, 1)
        $global:text_shuffle_hash[$text_shuffle_processed_char] = $text_shuffle_reversed_char
    }

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

    if ($salt_num_repeat -gt 0) {
        for ($i = 0; $i -lt $salt_num_repeat; $i++) {
            $pwd_salt=$password_processed.substring($password_processed.length-$salt_shuffle_idx);
            $pwd_salt = $pwd_salt[$pwd_salt.length..0] -join ""
            $global:password_processed="$($pwd_salt)$($password_processed.substring(0, $password_processed.length-$salt_shuffle_idx))"
        }
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

function encrypt_one_line {
    $global:error_one_line=""

    password_process;
    #$global:output_one_line=$global:input_one_line

    # first, perform the text shuffle
    $textShuffleSB = [System.Text.StringBuilder]::new()
    for ($j = 0; $j -lt $input_one_line.length; $j++) {
        # for characters not in the hashtable, let it be unconverted
        if ($null -eq $text_shuffle_hash["$($input_one_line[$j])"]) {
            [void]$textShuffleSB.append($($input_one_line[$j]))
        } else {
            [void]$textShuffleSB.append($text_shuffle_hash["$($input_one_line[$j])"])
        }
        
    }
    $global:output_one_line = $textShuffleSB.ToString();
    write-host "encrypt_one_line: global:output_one_line: [$global:output_one_line]"

    for ($i=0; $i -lt $encrypt_decrypt_rounds; $i++) {
        $output_one_line_bytes = [System.Text.Encoding]::ASCII.GetBytes($output_one_line)
        $output_one_line_b64=[Convert]::ToBase64String($output_one_line_bytes);
        $b64EncSB = [System.Text.StringBuilder]::new()
        for ($j = 0; $j -lt $output_one_line_b64.length; $j++) {
            [void]$b64EncSB.append($password_hash["$($output_one_line_b64[$j])"])
        }
        $output_one_line = $b64EncSB.ToString();
    }
    $global:output_one_line = "$salt_num_repeat" + "$salt_shuffle_idx" + "$encrypt_decrypt_rounds" + "$text_shuffle_version_supported" + $SALT_SEPARATOR + $output_one_line
}

function decrypt_one_line {
    extract_header_from_encrypted_text($input_one_line)
	$input_one_line_header_stripped=""
	$global:error_one_line=""
    if ($header_version -eq 2) {
        $input_one_line_header_stripped=$input_one_line.substring($HEADER_V2_LENGTH)
    } elseif ($header_version -eq 3) {
        $input_one_line_header_stripped=$input_one_line.substring($HEADER_V3_LENGTH)
    } elseif ($header_version -eq 4) {
        $input_one_line_header_stripped=$input_one_line.substring($HEADER_V4_LENGTH)
    }
    password_process
    $global:output_one_line=$input_one_line_header_stripped
    for ($i=0; $i -lt $encrypt_decrypt_rounds; $i++) {
        $b64DecSB = [System.Text.StringBuilder]::new()
        for ($j = 0; $j -lt $global:output_one_line.length; $j++) {
            [void]$b64DecSB.append($password_hash["$($global:output_one_line[$j])"])
        }
        try {
            $global:output_one_line = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b64DecSB.ToString())) 2>$null
        } catch {
            write-host "ERROR - you might have entered a wrong password"
            exit 1
        }
        if ([string]::IsNullOrEmpty($global:output_one_line)) {
            $global:error_one_line="ERROR - result is empty, you might have entered a wrong password" 
            return
        } 
        $global:output_one_line = stripLastLineFeedCharacter($global:output_one_line);
    }
    if ([string]::IsNullOrEmpty($global:output_one_line)) {
        $global:error_one_line="ERROR - result is empty, you might have entered a wrong password" 
    } else {
        # apply the text shuffle if header_version == 4
        if ($header_version -eq 4) {
            if ($text_shuffle_version_supported -eq 1) {
                $textShuffleSB = [System.Text.StringBuilder]::new()
                for ($j = 0; $j -lt $output_one_line.length; $j++) {
                    # for characters not in the hashtable, let it be unconverted
                    if ($null -eq $text_shuffle_hash["$($output_one_line[$j])"]) {
                        [void]$textShuffleSB.append($($output_one_line[$j]))
                    } else {
                        [void]$textShuffleSB.append($text_shuffle_hash["$($output_one_line[$j])"])
                    }
                }
                $global:output_one_line = $textShuffleSB.ToString();    
            } else {
                write-host  "ERROR - invalid text_shuffle_version_supported: [$text_shuffle_version_supported]"
				exit 1
            }
        }
    }
}

function do_work_on_stdin {
    if ($is_encrypt -eq $false) {
        $global:encrypted_from_stdin = Read-Host "Please type or paste the encrypted text"
    } else {
        $global:encrypted_from_stdin = Read-Host "Please type or paste the text to be encrypted"
    }
    
    ask_password;
    $global:input_one_line=$encrypted_from_stdin
    if ($is_encrypt -eq $false) {
        decrypt_one_line
        if (-Not [string]::IsNullOrEmpty($global:error_one_line)) {
            write-host $global:error_one_line
            exit 1
        } 
    } else {
        encrypt_one_line
    }

    if ($is_show_b64_charset -eq $true) {
        write-host "password_processed: [$password_processed]"
        write-host "password_reversed:  [$password_reversed]"
    }
    if ($is_copy_to_clipboard -eq $true) {
        Set-Clipboard -Value $global:output_one_line
        write-host ""
        write-host "The decrypted text is already copied to clipboard"
        write-host ""
    } else {
        write-host "$global:output_one_line"
    }
}

function do_work_on_filepath {
    ask_password
    Push-Location $filepath
    [Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
    if ($null -eq $filename) {
        write-host "do_work: filename is not defined, directory based"
        $files = Get-ChildItem .
        for($i=0; $i -lt $files.count; $i++) {
            do_work_on_a_file($files[$i].Name)
        }
    } else {
        write-host "do_work: filename is defined, specific file based"
        do_work_on_a_file($filename)
    }
    [void](Pop-Location)
}

function do_work_on_a_file($f) {
    $f_tmp1="$($f).1.tmp"
    $f_tmp2="$($f).2.tmp"
    $f_tmpPH=""
    $fB64="$($f).b64e"
    if ($is_strip_extension -eq $true) {
        $lastDotIdx = $f.lastindexof(".");
        $g = $f.substring(0,$lastDotIdx);
    } else {
        $g="$($f).$($arg_base64_option)"
    }
    $matched_text=""
    $results=""
    $results_with_tags=""
    $matched_found=$false

    if ($is_generate_results_in_file -eq $true) {
        write-host "do_work_on_a_file: will generate a file from: [$f] to:[$g]"
        [void](New-Item $g)
    }

    if ($mode -eq $MODE_FILE) {
        if ($is_encrypt -eq $true) {
            password_process
            Copy-Item -Path $f -Destination $f_tmp1
            for ($i = 0; $i -lt $encrypt_decrypt_rounds; $i++) {
                $by = [char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($f_tmp1));
                [IO.File]::WriteAllBytes($fB64, $by)
                $b64Tmp = [IO.File]::ReadAllText($fB64);
                $b64EncSB = [System.Text.StringBuilder]::new()
                for ($j = 0; $j -lt $b64Tmp.length; $j++) {
                    [void]$b64EncSB.append($password_hash["$($b64Tmp[$j])"])
                }
                [IO.File]::WriteAllText($f_tmp2, $b64EncSB.ToString())
                $f_tmpPH=$f_tmp1
                $f_tmp1=$f_tmp2
                $f_tmp2=$f_tmpPH
            }
            Add-Content -Path $g -Value "$($salt_num_repeat)$($salt_shuffle_idx)$($encrypt_decrypt_rounds)$($SALT_SEPARATOR)"
            $encryptedText = Get-Content -Path $f_tmp1
            Add-Content -Path $g -Value $encryptedText
        } else {
            $firstLine = Get-Content $f -First 1
            extract_header_from_encrypted_text($firstLine);
            password_process
            if ($header_version -ge 3) {
                (Get-Content $f| Select-Object -Skip 1) | Set-Content $f_tmp1
            } else {
                Copy-Item -Path $f -Destination $f_tmp1
            }
            for ($i = 0; $i -lt $encrypt_decrypt_rounds; $i++) {
                $encTmp = [IO.File]::ReadAllText($f_tmp1)
                $b64DecSB = [System.Text.StringBuilder]::new()
                for ($j = 0; $j -lt $encTmp.length; $j++) {
                    [void]$b64DecSB.append($password_hash["$($encTmp[$j])"])
                }
                [IO.File]::WriteAllText($fB64, $b64DecSB.ToString())
                $b64Txt = [char[]][IO.File]::ReadAllBytes($fB64);
                try {
                    $by = [Convert]::FromBase64String($b64Txt);
                } catch {
                    write-host "ERROR - you might have entered a wrong password"
                    Remove-Item -Path $f_tmp1
                    Remove-Item -Path $f_tmp2
                    Remove-Item -Path $fB64
                    exit 1
                }
                [IO.File]::WriteAllBytes($f_tmp2,$by);
                $f_tmpPH=$f_tmp1
                $f_tmp1=$f_tmp2
                $f_tmp2=$f_tmpPH
            }
            Copy-Item -Path $f_tmp1 -Destination $g
        }
        Remove-Item -Path $f_tmp1
        Remove-Item -Path $f_tmp2
        Remove-Item -Path $fB64
    } else {
        # $mode must be MODE_TAG here
        if ($is_generate_results_in_file -eq $false) {
            write-host "-----RESULTS START-----"
        }
        [System.IO.File]::ReadLines($f) | ForEach-Object {
            $tag_found=$false
            for($i=0; $i -lt $tag_keys.count; $i++) {
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

                        $global:input_one_line=$matched_text
                        if ($is_encrypt -eq $false) {
                            decrypt_one_line
                            if (-Not [string]::IsNullOrEmpty($global:error_one_line)) {
                                write-host $global:error_one_line
                            } 
                        } else {
                            encrypt_one_line
                        }
                        $results_with_tags="$tag_key_head$output_one_line$tag_key_tail"

                        if ($is_generate_results_in_file -eq $true) {
                            "$text_before_matched$results_with_tags$text_after_matched" >> $g
                        } else {
                            write-host "$text_before_matched$results_with_tags$text_after_matched"
                        }
                    }
                }
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
        if ($is_generate_results_in_file -eq $false) {
            write-host "-----RESULTS END-----"
        }        
    }
}

function stripLastLineFeedCharacter($string) {
    # if the last character of the string is of hex value "0x0a", or decimal "10", which in ascii table is the linefeed character
    # will return the string without it
    # this seems to be a problem when decrypting an encrypted string that was encrypted by the linux version (pck_encrypt_decrypt.sh)
    $lastCharStr = $string.substring($string.length - 1);
    $lastCharArray = $lastCharStr.toCharArray();
    $lastChar = $lastCharArray[$lastCharArray.length - 1];
    $lastCharToInt = [System.Convert]::ToUInt32($lastChar);
    if ($lastCharToInt -eq 10) {
        #write-host "stripLastLineFeedCharacter: lastCharToInt is 10, will strip"
        return $string.substring(0, $string.length - 1);
    }
    return $string;
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