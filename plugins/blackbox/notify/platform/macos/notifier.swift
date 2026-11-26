// Blackbox's notifier for macOS: one notification handed to the system, under Blackbox's name.
//
// Built into Blackbox.app (build.sh) and run by the dashboard (notify/platform/macos):
//
//   blackbox-notify send <title> <body> <id> <sound: 0|1>   → exit 0 "sent" | 3 "denied" | 5 "not-determined" | 4 "failed"
//   blackbox-notify status                                   → "authorized" | "denied" | "not-determined"
//   blackbox-notify request                                  → asks the person once; 0 "authorized" | 3 "denied"
//   blackbox-notify display                                  → "mirrored" | "single" (macOS hides banners on a mirrored display)
//   (no arguments — the person clicked a notification)      → opens Blackbox's dashboard
//
// `send` never asks: macOS shows its question only to a person in their desktop session, and an
// unanswered question is recorded as Off for good. The plugin asks with `request`, opened through
// LaunchServices (`open -n -g Blackbox.app --args request`) when the person is there; `request`
// then waits for their answer (up to `askSeconds`) instead of quitting under the question.
//
// It keeps no state and reads nothing but its arguments. The text it shows is written by the
// plugin (notify/wording.py), which keeps it safe for a lock screen.
import AppKit
import Foundation
import UserNotifications

let dashboard = "http://127.0.0.1:9700/#notifications"
let arguments = Array(CommandLine.arguments.dropFirst())
let center = UNUserNotificationCenter.current()

func finish(_ code: Int32, _ word: String) -> Never {
    print(word)
    exit(code)
}

func word(_ status: UNAuthorizationStatus) -> String {
    switch status {
    case .authorized, .provisional: return "authorized"
    case .denied: return "denied"
    default: return "not-determined"
    }
}

func ask(_ then: @escaping (Bool) -> Void) {
    center.requestAuthorization(options: [.alert, .sound]) { granted, _ in then(granted) }
}

func show(title: String, body: String, id: String, sound: Bool) {
    let content = UNMutableNotificationContent()
    content.title = title
    content.body = body
    if sound { content.sound = .default }
    center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil)) { error in
        finish(error == nil ? 0 : 4, error == nil ? "sent" : "failed")
    }
}

switch arguments.first ?? "" {
case "status":
    center.getNotificationSettings { finish(0, word($0.authorizationStatus)) }
case "request":
    ask { finish($0 ? 0 : 3, $0 ? "authorized" : "denied") }
case "send" where arguments.count >= 4:
    let (title, body, id) = (arguments[1], arguments[2], arguments[3])
    let sound = arguments.count > 4 && arguments[4] == "1"
    center.getNotificationSettings { settings in
        switch settings.authorizationStatus {
        case .denied: finish(3, "denied")
        case .notDetermined: finish(5, "not-determined")
        default: show(title: title, body: body, id: id, sound: sound)
        }
    }
case "display":
    var displays = [CGDirectDisplayID](repeating: 0, count: 16)
    var count: UInt32 = 0
    CGGetActiveDisplayList(16, &displays, &count)
    finish(0, displays.prefix(Int(count)).contains { CGDisplayIsInMirrorSet($0) != 0 } ? "mirrored" : "single")
case "":
    if let url = URL(string: dashboard) { NSWorkspace.shared.open(url) }
    exit(0)
default:
    finish(2, "usage: blackbox-notify send <title> <body> <id> <0|1> | status | request | display")
}
// The answers above arrive on another queue; wait for one (each path ends in exit). A question
// to the person waits for them; everything else answers within seconds.
let askSeconds = 600.0
DispatchQueue.main.asyncAfter(deadline: .now() + (arguments.first == "request" ? askSeconds : 20)) { finish(4, "timed-out") }
dispatchMain()
