import 'dart:io';

/// Debug log service that writes to stderr and optionally to a file.
/// No Flutter dependency — works in headless server and Flutter contexts.
class DebugLog {
  static DebugLog? _instance;
  static DebugLog get instance => _instance ??= DebugLog._();

  IOSink? _sink;
  String? _logFilePath;

  DebugLog._();

  /// Initialize the log file. Optional — if not called, logs go only to stderr.
  Future<void> init(String logPath) async {
    final file = File(logPath);
    await file.parent.create(recursive: true);
    _sink = file.openWrite(mode: FileMode.append);
    _logFilePath = logPath;
    log('=== Moat Dart server started ===');
  }

  /// Log a message with timestamp.
  void log(String message) {
    final now = DateTime.now();
    final timestamp = '${now.hour.toString().padLeft(2, '0')}:'
        '${now.minute.toString().padLeft(2, '0')}:'
        '${now.second.toString().padLeft(2, '0')}.'
        '${now.millisecond.toString().padLeft(3, '0')}';
    final line = '[$timestamp] $message';
    _sink?.writeln(line);
    stderr.writeln(line);
  }

  String? get logFilePath => _logFilePath;

  Future<void> close() async {
    await _sink?.flush();
    await _sink?.close();
    _sink = null;
  }
}

/// Global log function for convenience.
void moatLog(String message) {
  DebugLog.instance.log(message);
}
