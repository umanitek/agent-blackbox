// Draws one SVG into a square PNG with its transparency kept: the notifier's icon is built from
// the dashboard's own Blackbox mark (dashboard/assets/blackbox-mark.svg — the tab icon), so the
// app in System Settings → Notifications looks like Blackbox. Run by icon.sh at build time.
//
//   icon <svg> <png out> <size in pixels>
//
// WHY not `qlmanage -t`: its thumbnail paints the picture on an opaque white tile.
import AppKit

let words = CommandLine.arguments
guard words.count == 4, let size = Int(words[3]), size > 0, let picture = NSImage(contentsOfFile: words[1]),
      let canvas = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
                                    samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                    bytesPerRow: 0, bitsPerPixel: 0) else {
    FileHandle.standardError.write("usage: icon <svg> <png> <size>\n".data(using: .utf8)!)
    exit(2)
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: canvas)
picture.draw(in: NSRect(x: 0, y: 0, width: size, height: size))
NSGraphicsContext.restoreGraphicsState()
guard let png = canvas.representation(using: .png, properties: [:]),
      (try? png.write(to: URL(fileURLWithPath: words[2]))) != nil else { exit(1) }
