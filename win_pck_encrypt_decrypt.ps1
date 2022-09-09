$arg_filepath=$args[0];
$arg_base64_option=$args[1];
$arg_tag_key=$args[2];
#write-host "aaa: param1:$($param1);" 

$encode_extension="b64e";
$decode_extension="b64d";

$ARG_KEY_ENCRYPT_IN_MEMORY="enc";
$ARG_KEY_DECRYPT_IN_MEMORY="dec";
$ARG_KEY_ENCRYPT_IN_FILE="encf";
$ARG_KEY_DECRYPT_IN_FILE="decf";

$global:filename=""
$global:filepath=""
$tag_key_head=""
$tag_key_tail=""

$global:password_from_stdin=""
$global:password_processed=""
$global:password_reversed=""
$global:password_hash=New-Object system.collections.hashtable
$result_filename_suffix=""
$global:is_process_whole_file=$false;
$globalis_generate_results_in_file=$false;
$global:is_encrypt=$false;
$global:tag_keys=@();

$SALT_SEPARATOR="-"
$SALT_LENGTH=3
$is_salt_used=$false
$salt_num_repeat=0
$salt_shuffle_idx=0

$base64_charset="/+9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

function print_usage_and_exit {
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

function arguments_check {
    if (($null -eq $arg_filepath) -or ($null -eq $arg_base64_option)) {
        write-host "arguments_check: ERROR - not all arguments are specified"
        print_usage_and_exit;
    }

    if ($ARG_KEY_ENCRYPT_IN_MEMORY -eq $arg_base64_option) {
        $global:is_generate_results_in_file=$false;
		$global:is_encrypt=$true;
    } elseif ($ARG_KEY_DECRYPT_IN_MEMORY -eq $arg_base64_option) {
        $global:is_generate_results_in_file=$false;
		$global:is_encrypt=$false;
    } elseif ($ARG_KEY_ENCRYPT_IN_FILE -eq $arg_base64_option) {
        $global:is_generate_results_in_file=$true;
		$global:is_encrypt=$true;
    } elseif ($ARG_KEY_DECRYPT_IN_FILE -eq $arg_base64_option) {
        $global:is_generate_results_in_file=$true;
		$global:is_encrypt=$false;
    } else {
        write-host "arguments_check: ERROR - arg_base64_option is not specified correctly: $($arg_base64_option);";
		print_usage_and_exit
    }

    #write-host "__is_generate_results_in_file:$($is_generate_results_in_file);";
    #write-host "__is_encrypt:$($is_encrypt);";

    if (Test-Path $arg_filepath -PathType Leaf) {
        write-host "1.0;";
        $global:filepath=(Get-Item $arg_filepath ).DirectoryName;
        $global:filename=(Get-Item $arg_filepath ).Name;
    } elseif (Test-Path $arg_filepath) {
        write-host "2.0;";
        $global:filepath=(Get-Item $arg_filepath ).FullName;
        $global:filename=$null;
    } else {
        write-host "arguments_check: ERROR - [$($arg_filepath)] is not a valid file or directory";
        print_usage_and_exit;
    } 

    #write-host "arguments_check: arg_filepath: [$($arg_filepath)]"
    #write-host "arguments_check: arg_base64_option: [$($arg_base64_option)]"
    #write-host "arguments_check: filepath:$($filepath);";
    #write-host "arguments_check: filename:$($filename);";

    if ($null -eq $arg_tag_key) {
        $global:is_process_whole_file=$true
        #write-host "arguments_check: is_process_whole_file=true;"
    } else {
        $global:is_process_whole_file=$false
        #write-host "arguments_check: is_process_whole_file=false;"
        #write-host "arguments_check: tag keys:";
        $global:tag_keys = $arg_tag_key.Split(",");
        <#
        for($i=0; $i -lt $tag_keys.Length; $i++) {
            write-host "[$($tag_keys[$i])];"
        }
        #>
    }
}

function ask_password {
    $password_confirm_from_stdin=""
    $password_from_stdin_secure = Read-Host 'Please enter the password' -AsSecureString
    $global:password_from_stdin = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_from_stdin_secure));
    if ($is_encrypt -eq $true) {
        $password_confirm_from_stdin_secure = Read-Host 'Please re-enter the password' -AsSecureString
        $password_confirm_from_stdin = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_confirm_from_stdin_secure));
        if ($password_from_stdin -cne $password_confirm_from_stdin) {
            write-host "ERROR - password entered do not match.";
            Exit 1;
        }
    }
}

function password_process {
    write-host "password_process: 1.0;"
    $combined_password_base64_charset="$($password_from_stdin)$($base64_charset)"
    $global:password_processed=""    
    for ($i=0; $i -lt $combined_password_base64_charset.length; $i++) {
        $thisChar=$combined_password_base64_charset.substring($i, 1)
        if ($global:password_processed.contains($thisChar)) {
            # do nothing
        } else {
            $global:password_processed="$($global:password_processed)$($thisChar)"
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

function do_work {
    write-host "do_work: filepath:[$($filepath)];";
    write-host "do_work: filename:[$($filename)];";
    write-host "do_work: password_from_stdin:[$($password_from_stdin)];"
    write-host "do_work: is_process_whole_file:[$($is_process_whole_file)];"
    write-host "do_work: is_encrypt:[$($is_encrypt)];"
    write-host "do_work: is_generate_results_in_file:[$($is_generate_results_in_file)];"
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
    Pop-Location

}

function do_work_on_a_file($f) {
    $fB64="$($f).b64e"
    $g="$($f).$($arg_base64_option)"
    write-host "do_work_on_a_file: f:[$($f)]; g:[$($g)];"
    $matched_text=""
    $result=""
    $results_with_tags=""
    $matched_found=$false

    if ($is_generate_results_in_file -eq $true) {
        write-host "do_work_on_a_file: will generate a file from: [$f] to:[$g]"
        #New-Item $g
    }

    if ($is_process_whole_file -eq $true) {
        password_process
        if ($is_generate_results_in_file -eq $false -and $is_encrypt -eq $true) {
            write-host "do_work_on_a_file: 1.0"
            $by = [char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($f));
            [IO.File]::WriteAllBytes($fB64, $by)
            $b64Tmp = [IO.File]::ReadAllText($fB64);
            $b64EncSB = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $b64Tmp.length; $i++) {
                [void]$b64EncSB.append($password_hash["$($b64Tmp[$i])"])
            }
            write-host $b64EncSB.ToString()
        } elseif ($is_generate_results_in_file -eq $true -and $is_encrypt -eq $true) {
            write-host "do_work_on_a_file: 2.0"
            $by = [char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($f));
            [IO.File]::WriteAllBytes($fB64, $by)
            $b64Tmp = [IO.File]::ReadAllText($fB64);
            $b64EncSB = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $b64Tmp.length; $i++) {
                [void]$b64EncSB.append($password_hash["$($b64Tmp[$i])"])
            }
            [IO.File]::WriteAllText($g, $b64EncSB.ToString())
        } elseif ($is_generate_results_in_file -eq $false -and $is_encrypt -eq $false) {
            write-host "do_work_on_a_file: 3.0"
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
            write-host "do_work_on_a_file: 4.0;"
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
        write-host "do_work_on_a_file: 5.0 ERROR - function to be implemented..."
    }
}

write-host "win_pck_encrypt_decrypt: v0.2 START;";

arguments_check;
ask_password;
do_work;
exit 0;