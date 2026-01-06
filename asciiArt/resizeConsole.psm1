function Resize-Console {
    param([int]$Width = 150)
    $RawUI = $Host.UI.RawUI
    if ($RawUI.WindowSize.Width -lt $Width) {
        try {
            # Resize Buffer first (must be >= Window width)
            $B = $RawUI.BufferSize
            if ($B.Width -lt $Width) { $B.Width = $Width; $RawUI.BufferSize = $B }
            # Resize Window second
            $W = $RawUI.WindowSize
            $W.Width = $Width; $RawUI.WindowSize = $W
            Write-Host "Resized terminal to $Width width." -ForegroundColor Gray
        } catch {
            Write-Warning "Cannot automatically resize this terminal window."
        }
    }
}
