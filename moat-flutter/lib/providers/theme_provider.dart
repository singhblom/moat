import 'package:flutter/material.dart';

/// Manages the app's theme mode (light/dark/system).
class ThemeProvider extends ChangeNotifier {
  ThemeMode _themeMode = ThemeMode.system;

  ThemeMode get themeMode => _themeMode;

  void toggleTheme(Brightness currentBrightness) {
    // If currently dark, switch to light; if currently light, switch to dark.
    _themeMode = currentBrightness == Brightness.dark
        ? ThemeMode.light
        : ThemeMode.dark;
    notifyListeners();
  }
}
