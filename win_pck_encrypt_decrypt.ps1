$filepath=$args[0]
$mode=$args[1]
#write-host "aaa: param1:$($param1);" 

$encode_extension="b64e";
$decode_extension="b64d";

write-host "win_pck_encrypt_decrypt: v0.1 START;";

if (-not (Test-Path $filepath -PathType Leaf)) {
    write-host "win_pck_encrypt_decrypt_win: ERROR - file [$($filepath)] not exists; exiting...";
    Exit 1
} 

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