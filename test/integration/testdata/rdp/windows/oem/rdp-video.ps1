# The video scene of the Windows measurement (ADR-0090, lot A): started at every logon, hidden, by
# rdp-setup.ps1's Run entry. The Windows key does not reach the shell (PR #101), so the test cannot
# start a program from the keyboard: it asks by a file on the share, as the logoff test does. Each
# new video-request (its write time changes) plays one scene: a borderless window over the whole
# screen, every pixel changing 25 times a second, in 8-pixel blocks of random colour — the worst
# case for PNG, an upper bound for a video. The scene lasts the seconds the file holds (10 by
# default, 60 at most), then the window closes and the desktop is as before.
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

$shares = @('\\host.lan\Data')
$gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
if ($gateway) { $shares += "\\$gateway\Data" }
$log = Join-Path $env:TEMP 'rdp-video.log'
function Note($text) {
  $line = "$(Get-Date -Format o) $text"
  Add-Content $log $line -ErrorAction SilentlyContinue
  foreach ($share in $shares) { Add-Content (Join-Path $share "video-status-$env:USERNAME.txt") $line -ErrorAction SilentlyContinue }
}

function Play([int]$seconds) {
  $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $block = 8
  $w, $h = [math]::Ceiling($screen.Width / $block), [math]::Ceiling($screen.Height / $block)
  $small = New-Object System.Drawing.Bitmap $w, $h, ([System.Drawing.Imaging.PixelFormat]::Format32bppRgb)
  $bytes = New-Object byte[] ($w * $h * 4)
  $random = New-Object System.Random
  $form = New-Object System.Windows.Forms.Form
  $form.FormBorderStyle = 'None'
  $form.StartPosition = 'Manual'
  $form.Bounds = $screen
  $form.TopMost = $true
  $form.ShowInTaskbar = $false
  $box = New-Object System.Windows.Forms.PictureBox
  $box.Dock = 'Fill'
  $box.SizeMode = 'Normal'
  $big = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height, ([System.Drawing.Imaging.PixelFormat]::Format32bppRgb)
  $g = [System.Drawing.Graphics]::FromImage($big)
  # Nearest-neighbour and pixel-aligned, so the blocks stay sharp-edged when enlarged.
  $g.InterpolationMode = 'NearestNeighbor'
  $g.PixelOffsetMode = 'Half'
  $form.Controls.Add($box)
  $script:frames = 0
  $stopAt = (Get-Date).AddSeconds($seconds)
  $timer = New-Object System.Windows.Forms.Timer
  $timer.Interval = 40
  $timer.Add_Tick({
    if ((Get-Date) -ge $stopAt) { $timer.Stop(); $form.Close(); return }
    $random.NextBytes($bytes)
    $data = $small.LockBits((New-Object System.Drawing.Rectangle 0, 0, $w, $h), 'WriteOnly', $small.PixelFormat)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $data.Scan0, $bytes.Length)
    $small.UnlockBits($data)
    $g.DrawImage($small, 0, 0, $screen.Width, $screen.Height)
    $box.Image = $big
    $box.Refresh()
    $script:frames++
  })
  $form.Add_Shown({ $timer.Start() })
  [System.Windows.Forms.Application]::Run($form)
  $timer.Dispose(); $form.Dispose(); $g.Dispose(); $big.Dispose(); $small.Dispose()
  return $script:frames
}

Note "watching for video-request on $($shares -join ', ')"
$seen = @{}
foreach ($share in $shares) {
  $item = Get-Item (Join-Path $share 'video-request') -ErrorAction SilentlyContinue
  if ($item) { $seen[$share] = $item.LastWriteTimeUtc } # a request older than this logon is not one
}
while ($true) {
  foreach ($share in $shares) {
    $item = Get-Item (Join-Path $share 'video-request') -ErrorAction SilentlyContinue
    if ($item -and $seen[$share] -ne $item.LastWriteTimeUtc) {
      $seen[$share] = $item.LastWriteTimeUtc
      $seconds = 10
      $asked = (Get-Content $item.FullName -Raw -ErrorAction SilentlyContinue)
      if ($asked -match '^\s*(\d+)') { $seconds = [math]::Min([int]$Matches[1], 60) }
      Note "playing $seconds s"
      try { $frames = Play $seconds; Note "played: $frames frame(s)" } catch { Note "failed: $_" }
    }
  }
  Start-Sleep -Milliseconds 250
}
