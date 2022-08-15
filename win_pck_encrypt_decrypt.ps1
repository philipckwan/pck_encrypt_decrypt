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


$is_process_whole_file=$false;
$is_generate_results_in_file=$false;
$global:is_encrypt=$false;

$tag_keys=@();

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

function arguments_check {
    if (($null -eq $arg_filepath) -or ($null -eq $arg_base64_option)) {
        write-host "arguments_check: ERROR - not all arguments are specified"
        print_usage_and_exit;
    }

    if ($ARG_KEY_ENCRYPT_IN_MEMORY -eq $arg_base64_option) {
        $is_generate_results_in_file=$false;
		$global:is_encrypt=$true;
    } elseif ($ARG_KEY_DECRYPT_IN_MEMORY -eq $arg_base64_option) {
        $is_generate_results_in_file=$false;
		$global:is_encrypt=$false;
    } elseif ($ARG_KEY_ENCRYPT_IN_FILE -eq $arg_base64_option) {
        $is_generate_results_in_file=$true;
		$global:is_encrypt=$true;
    } elseif ($ARG_KEY_DECRYPT_IN_FILE -eq $arg_base64_option) {
        $is_generate_results_in_file=$true;
		$global:is_encrypt=$false;
    } else {
        write-host "arguments_check: ERROR - arg_base64_option is not specified correctly: $($arg_base64_option);";
		print_usage_and_exit
    }

    write-host "__is_generate_results_in_file:$($is_generate_results_in_file);";
    write-host "__is_encrypt:$($is_encrypt);";

    if (Test-Path $arg_filepath -PathType Leaf) {
        write-host "1.0;";
        $filepath=(Get-Item $arg_filepath ).DirectoryName;
        $filename=(Get-Item $arg_filepath ).Name;
    } elseif (Test-Path $arg_filepath) {
        write-host "2.0;";
        $filepath=(Get-Item $arg_filepath ).FullName;
        $filename=$null;
    } else {
        write-host "arguments_check: ERROR - file [$($filepath)] not exists; exiting...";
        print_usage_and_exit;
    } 

    write-host "arguments_check: filepath:$($filepath);";
    write-host "arguments_check: filename:$($filename);";

    if (-not ($null -eq $arg_tag_key)) {
        write-host "arguments_check: arg_tag_key:$($arg_tag_key);";
        $tag_keys = $arg_tag_key.Split("-");
        for($i=0; $i -lt $tag_keys.Length; $i++) {
            write-host "tag_keys[$($i)]:$($tag_keys[$i]);"
        }
    }
}

function ask_password {
    write-host "__is_encrypt:$($is_encrypt);";
    $password_confirm_from_stdin=""
    $password_from_stdin = Read-Host 'Please enter the password' -AsSecureString
    $password_from_stdin_plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_from_stdin));
    if ($is_encrypt -eq $true) {
        $password_confirm_from_stdin = Read-Host 'Please re-enter the password' -AsSecureString
        $password_confirm_from_stdin_plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_confirm_from_stdin));
        if ($password_from_stdin_plaintext -cne $password_confirm_from_stdin_plaintext) {
            write-host "ERROR - password entered do not match.";
            Exit 1;
        }
    }
    write-host "ask_password: password:[$($password_from_stdin_plaintext)];";
}
function do_work {
    write-host "do_work: 1.0;";
}

function doEncryptionDecryption {
    if ($mode -eq "enc") {
        $outfilepath="$($filepath).$($encode_extension)";
        write-host "win_pck_encrypt_decrypt_win: will Base64 encode this file:[$($filepath)] to file:[$($outfilepath)]";
        $by = [char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($filepath));
        [IO.File]::WriteAllBytes($outfilepath,$by);
        #[IO.File]::WriteAllBytes($outfilepath,[char[]][Convert]::ToBase64String([IO.File]::ReadAllBytes($filepath)));
    } else {
        $outfilepath="$($filepath).$($decode_extension)";
        write-host "winpck_encrypt_decrypt_win: will Base64 decode this file:[$($filepath)] to file:[$($outfilepath)];";
        $b64Txt = [char[]][IO.File]::ReadAllBytes($filepath);
        $by = [Convert]::FromBase64String($b64Txt);
        [IO.File]::WriteAllBytes($outfilepath,$by);
        #[IO.File]::WriteAllBytes($outfilepath, [Convert]::FromBase64String([char[]][IO.File]::ReadAllBytes($filepath)));
        
    }
}

write-host "win_pck_encrypt_decrypt: v0.1 START;";

arguments_check;
ask_password;
do_work;
exit 0;