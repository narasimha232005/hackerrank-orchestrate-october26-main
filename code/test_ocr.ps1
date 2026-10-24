Add-Type -AssemblyName System.Drawing
[Windows.Globalization.Language, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.StorageFile, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null

$imagePath = (Resolve-Path "dataset\evidence\images\marketing_profile_console.png").Path
$fileTask = [Windows.Storage.StorageFile]::GetFileFromPathAsync($imagePath).AsTask()
$fileTask.Wait()
$file = $fileTask.Result

$streamTask = $file.OpenAsync([Windows.Storage.FileAccessMode]::Read).AsTask()
$streamTask.Wait()
$stream = $streamTask.Result

$decoderTask = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream).AsTask()
$decoderTask.Wait()
$decoder = $decoderTask.Result

$bitmapTask = $decoder.GetSoftwareBitmapAsync().AsTask()
$bitmapTask.Wait()
$bitmap = $bitmapTask.Result

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($engine -eq $null) {
    $lang = [Windows.Globalization.Language]::new("en-US")
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
}

$ocrTask = $engine.RecognizeAsync($bitmap).AsTask()
$ocrTask.Wait()
$ocrResult = $ocrTask.Result

Write-Host "OCR Text:"
Write-Host $ocrResult.Text
