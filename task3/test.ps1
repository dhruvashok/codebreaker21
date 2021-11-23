$bytes = [System.IO.File]::ReadAllBytes("./pressure")

$prev = [byte] 195

$dec = $(for ($i = 0; $i -lt $bytes.length; $i++) {
    $prev = $bytes[$i] -bxor $prev
    $prev
})

$dec = [System.Text.Encoding]::UTF8.GetString($dec)
Write-Host $dec
# iex([System.Text.Encoding]::UTF8.GetString($dec))