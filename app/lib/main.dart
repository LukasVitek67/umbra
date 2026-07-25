// SPDX-License-Identifier: AGPL-3.0-or-later
import 'package:flutter/material.dart';

import 'accounts_screen.dart';
import 'connecting.dart';
import 'profile_button.dart';
import 'l10n.dart';
import 'mock.dart';
import 'screens_chats.dart';
import 'screens_more.dart';
import 'src/rust/frb_generated.dart';
import 'theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await L.load();
  await UmbraTheme.load();
  runApp(const UmbraAppRoot());
}

class UmbraAppRoot extends StatelessWidget {
  const UmbraAppRoot({super.key});

  @override
  Widget build(BuildContext context) {
    // The theme sits outermost: changing it rebuilds every screen below.
    return ValueListenableBuilder<UmbraPalette>(
      valueListenable: UmbraTheme.notifier,
      builder: (context, _, _) => MaterialApp(
        title: 'Umbra',
        debugShowCheckedModeBanner: false,
        theme: umbraTheme(),
        home: ValueListenableBuilder<String>(
          valueListenable: languageNotifier,
          builder: (context, _, _) => ListenableBuilder(
            listenable: appState,
            builder: (context, _) {
              if (!appState.hasIdentity) return const StartupGate();
              // Nothing works before Tor is up, so show the progress instead of
              // an empty app the user would poke at in vain.
              if (!appState.torConnected) return const ConnectingScreen();
              return const HomeShell();
            },
          ),
        ),
      ),
    );
  }
}

/// The Umbra brand mark: a rounded shield with a soft accent glow.
class UmbraMark extends StatelessWidget {
  const UmbraMark({super.key, this.size = 72});
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF1E2A2A), Color(0xFF102523)],
        ),
        borderRadius: BorderRadius.circular(size * 0.28),
        border: Border.all(color: UmbraColors.accent.withValues(alpha: 0.5)),
        boxShadow: [
          BoxShadow(
            color: UmbraColors.accent.withValues(alpha: 0.25),
            blurRadius: 24,
            spreadRadius: -4,
          ),
        ],
      ),
      child: Icon(Icons.shield_moon_rounded, size: size * 0.5, color: UmbraColors.accent),
    );
  }
}

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _username = TextEditingController();
  final _pass = TextEditingController();
  final _confirm = TextEditingController();
  bool _obscure = true;
  bool _busy = false;
  bool _remember = false;

  @override
  void dispose() {
    _username.dispose();
    _pass.dispose();
    _confirm.dispose();
    super.dispose();
  }

  bool get _valid =>
      _username.text.trim().isNotEmpty &&
      _pass.text.length >= 8 &&
      _pass.text == _confirm.text;

  Future<void> _submit() async {
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _busy = true);
    final ok = await appState.createAccount(
      _username.text,
      _pass.text,
      autologin: _remember,
    );
    if (!ok && mounted) {
      setState(() => _busy = false);
      messenger.showSnackBar(SnackBar(content: Text(appState.lastError ?? 'Chyba')));
    }
    // On success the app root swaps to HomeShell automatically.
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Center(child: UmbraMark(size: 84)),
                const SizedBox(height: 24),
                Text('Umbra',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontSize: 34)),
                const SizedBox(height: 8),
                Text(
                  L.t('app.tagline'),
                  textAlign: TextAlign.center,
                  style: TextStyle(color: UmbraColors.textMuted, height: 1.4),
                ),
                const SizedBox(height: 36),
                Text(L.t('onboard.create.title'),
                    style: const TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                Text(
                  L.t('onboard.create.subtitle'),
                  style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                ),
                const SizedBox(height: 16),
                ...[
                  TextField(
                    controller: _username,
                    onChanged: (_) => setState(() {}),
                    textInputAction: TextInputAction.next,
                    decoration: InputDecoration(
                      hintText: L.t('onboard.username'),
                      prefixIcon: Icon(Icons.person_outline, color: UmbraColors.textMuted),
                    ),
                  ),
                  const SizedBox(height: 12),
                ],
                TextField(
                  controller: _pass,
                  obscureText: _obscure,
                  onChanged: (_) => setState(() {}),
                  onSubmitted: (_) {
                    if (_valid && !_busy) _submit();
                  },
                  decoration: InputDecoration(
                    hintText: L.t('onboard.passphrase'),
                    prefixIcon: Icon(Icons.lock_outline, color: UmbraColors.textMuted),
                    suffixIcon: IconButton(
                      icon: Icon(_obscure ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                          color: UmbraColors.textMuted),
                      onPressed: () => setState(() => _obscure = !_obscure),
                    ),
                  ),
                ),
                ...[
                  const SizedBox(height: 12),
                  TextField(
                    controller: _confirm,
                    obscureText: _obscure,
                    onChanged: (_) => setState(() {}),
                    decoration: InputDecoration(
                      hintText: L.t('onboard.repeat'),
                      prefixIcon: Icon(Icons.lock_outline, color: UmbraColors.textMuted),
                    ),
                  ),
                ],
                const SizedBox(height: 20),
                CheckboxListTile(
                  value: _remember,
                  onChanged: (v) => setState(() => _remember = v ?? false),
                  controlAffinity: ListTileControlAffinity.leading,
                  contentPadding: EdgeInsets.zero,
                  dense: true,
                  title: Text(L.t('accounts.remember'),
                      style: TextStyle(fontSize: 13, color: UmbraColors.textPrimary)),
                  subtitle: Text(L.t('accounts.rememberHelp'),
                      style: TextStyle(fontSize: 11, color: UmbraColors.textMuted)),
                ),
                FilledButton(
                  onPressed: (_valid && !_busy) ? _submit : null,
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: _busy
                        ? SizedBox(
                            height: 20,
                            width: 20,
                            child: CircularProgressIndicator(strokeWidth: 2, color: UmbraColors.accentInk),
                          )
                        : Text(L.t('onboard.create.button')),
                  ),
                ),
                const SizedBox(height: 16),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(Icons.info_outline, size: 14, color: UmbraColors.textMuted),
                    const SizedBox(width: 6),
                    Flexible(
                      child: Text(
                        L.t('app.experimental'),
                        style: TextStyle(color: UmbraColors.textMuted, fontSize: 12),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;
  Chat? _selected;
  GroupChat? _selectedGroup;

  /// The middle column: whichever section the rail has selected.
  Widget _section() {
    switch (_index) {
      // Devices moved under Settings — it is not a place you visit often.
      case 1:
        return const SettingsScreen();
      default:
        return ChatsScreen(
          selectedHex: _selected?.contactHex,
          // Only one conversation is open at a time, be it a person or a group.
          onSelect: (chat) => setState(() {
            _selected = chat;
            _selectedGroup = null;
          }),
          selectedGroupHex: _selectedGroup?.idHex,
          onSelectGroup: (group) => setState(() {
            _selectedGroup = group;
            _selected = null;
          }),
        );
    }
  }

  /// The open conversation, or null when the user has not picked one.
  Widget? _conversation({required bool embedded}) {
    if (_selectedGroup != null) {
      return GroupDetailScreen(
        key: ValueKey(_selectedGroup!.idHex),
        group: _selectedGroup!,
        embedded: embedded,
        onBack: () => setState(() => _selectedGroup = null),
        onLeft: () => setState(() => _selectedGroup = null),
      );
    }
    if (_selected != null) {
      return ChatDetailScreen(
        key: ValueKey(_selected!.contactHex),
        chat: _selected!,
        embedded: embedded,
        onBack: () => setState(() => _selected = null),
      );
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          // Top bar: the account you are signed in as lives here.
          Container(
            height: 44,
            decoration: BoxDecoration(
              color: UmbraColors.surface,
              border: Border(bottom: BorderSide(color: UmbraColors.border)),
            ),
            child: const Row(
              children: [
                Spacer(),
                ProfileButton(),
                SizedBox(width: 6),
              ],
            ),
          ),
          // A finished update is worth one line at the top; it needs a restart
          // and the user should not have to find that in Settings.
          ListenableBuilder(
            listenable: appState,
            builder: (context, _) {
              final ready = appState.updateReadyVersion;
              if (ready == null) return const SizedBox.shrink();
              return Container(
                width: double.infinity,
                color: UmbraColors.accent.withValues(alpha: 0.12),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: Row(
                  children: [
                    Icon(Icons.system_update_alt, size: 16, color: UmbraColors.accent),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        L.t('update.banner').replaceAll('{v}', ready),
                        style: TextStyle(color: UmbraColors.textPrimary, fontSize: 12),
                      ),
                    ),
                    TextButton(
                      onPressed: appState.restartForUpdate,
                      child: Text(L.t('update.restart')),
                    ),
                  ],
                ),
              );
            },
          ),
          Expanded(child: _shell()),
        ],
      ),
    );
  }

  Widget _shell() {
    return LayoutBuilder(
        builder: (context, constraints) {
          // Below this width a two-pane layout would squeeze both panes, so we
          // fall back to one pane at a time (list, then conversation).
          final wide = constraints.maxWidth >= 820;

          final rail = NavigationRail(
            selectedIndex: _index,
            onDestinationSelected: (i) => setState(() => _index = i),
            labelType: NavigationRailLabelType.all,
            leading: const Padding(
              padding: EdgeInsets.symmetric(vertical: 16),
              child: UmbraMark(size: 40),
            ),
            destinations: [
              NavigationRailDestination(
                  icon: const Icon(Icons.forum_outlined),
                  selectedIcon: const Icon(Icons.forum),
                  label: Text(L.t('nav.chats'))),
              NavigationRailDestination(
                  icon: const Icon(Icons.settings_outlined),
                  selectedIcon: const Icon(Icons.settings),
                  label: Text(L.t('nav.settings'))),
            ],
          );

          if (!wide) {
            // Narrow window: the conversation covers the list while it is open.
            final open = _index == 0 ? _conversation(embedded: false) : null;
            return Row(
              children: [
                rail,
                const VerticalDivider(width: 1),
                Expanded(child: open ?? _section()),
              ],
            );
          }

          return Row(
            children: [
              rail,
              const VerticalDivider(width: 1),
              // Chat list (or the other sections) on the left half.
              SizedBox(
                width: constraints.maxWidth.clamp(0, 1600) * 0.30 + 60,
                child: _section(),
              ),
              const VerticalDivider(width: 1),
              // The open conversation fills the rest.
              Expanded(child: _conversation(embedded: true) ?? const NoChatSelected()),
            ],
          );
        },
    );
  }
}

/// Decides what a launch looks like: straight into an account that signs in
/// automatically, the account picker, or first-run account creation.
class StartupGate extends StatefulWidget {
  const StartupGate({super.key});

  @override
  State<StartupGate> createState() => _StartupGateState();
}

class _StartupGateState extends State<StartupGate> {
  bool _checked = false;
  bool _any = false;

  @override
  void initState() {
    super.initState();
    _check();
  }

  Future<void> _check() async {
    final accounts = await appState.accounts();
    // Exactly one account that remembers its passphrase: skip the picker.
    if (accounts.length == 1 && accounts.first.autologin) {
      if (await appState.signInAuto(accounts.first.id)) return;
    }
    if (mounted) {
      setState(() {
        _any = accounts.isNotEmpty;
        _checked = true;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!_checked) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    // No accounts yet, or the user asked to add one → the create form.
    if (!_any || appState.creatingAccount) return const OnboardingScreen();
    return const AccountPickerScreen();
  }
}
