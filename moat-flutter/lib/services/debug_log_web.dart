import 'package:flutter/foundation.dart';

/// Web debug log service — logs to console only (no file I/O on web).
class DebugLog {
  static DebugLog? _instance;
  static DebugLog get instance => _instance ??= DebugLog._();

  DebugLog._();

  /// No-op on web (no file system)
  Future<void> init() async {
    debugPrint('=== Moat Flutter started (web, console-only logging) ===');
  }

  /// Log a message with timestamp
  void log(String message) {
    final now = DateTime.now();
    final timestamp = '${now.hour.toString().padLeft(2, '0')}:'
        '${now.minute.toString().padLeft(2, '0')}:'
        '${now.second.toString().padLeft(2, '0')}.'
        '${now.millisecond.toString().padLeft(3, '0')}';

    debugPrint('[$timestamp] $message');
  }

  /// No log file on web
  String? get logFilePath => null;

  /// No-op on web
  Future<void> close() async {}
}

/// Global log function for convenience
void moatLog(String message) {
  DebugLog.instance.log(message);
}
