import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

/// Simple debug log service that writes to both console and file
class DebugLog {
  static DebugLog? _instance;
  static DebugLog get instance => _instance ??= DebugLog._();

  File? _logFile;
  IOSink? _sink;

  DebugLog._();

  /// Initialize the log file
  Future<void> init() async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      _logFile = File('${dir.path}/moat_debug.log');

      // Append to existing log
      _sink = _logFile!.openWrite(mode: FileMode.append);

      // Force print the path to console so we know where the file is
      // ignore: avoid_print
      print('=== MOAT LOG FILE: ${_logFile!.path} ===');
      log('=== Moat Flutter started ===');
    } catch (e) {
      debugPrint('Failed to initialize log file: $e');
    }
  }

  /// Log a message with timestamp
  void log(String message) {
    final now = DateTime.now();
    final timestamp = '${now.hour.toString().padLeft(2, '0')}:'
        '${now.minute.toString().padLeft(2, '0')}:'
        '${now.second.toString().padLeft(2, '0')}.'
        '${now.millisecond.toString().padLeft(3, '0')}';

    final line = '[$timestamp] $message';

    // Print to console
    // debugPrint(line);

    // Write to file
    _sink?.writeln(line);
  }

  /// Get the log file path
  String? get logFilePath => _logFile?.path;

  /// Flush and close the log
  Future<void> close() async {
    await _sink?.flush();
    await _sink?.close();
    _sink = null;
  }
}

/// Global log function for convenience
void moatLog(String message) {
  DebugLog.instance.log(message);
}
