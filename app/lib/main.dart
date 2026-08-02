// SPDX-License-Identifier: AGPL-3.0-or-later
import 'dart:io';

import 'package:flutter/material.dart';

import 'accounts_screen.dart';
import 'autostart.dart';
import 'background.dart';
import 'connecting.dart';
import 'profile_button.dart';
import 'l10n.dart';
import 'mock.dart';
import 'passphrase_vault.dart';
import 'native_dir.dart';
import 'notifications.dart';
import 'screens_chats.dart';
import 'screens_media.dart';
import 'screens_more.dart';
import 'single_instance.dart';
import 'src/rust/frb_generated.dart';
import 'theme.dart';

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();

  // Before anything heavy: a second NullChat would fight the first one for Tor's
  // data directory (and neither would connect), so hand over and quit instead.
  final mine = await SingleInstance.acquire(
    onSecondLaunch: () => BackgroundMode.instance.show(),
    replacing: args.contains(kRestartFlag),
  );
  if (!mine) {
    exit(0);
  }

  await RustLib.init();
  await L.load();
  await UmbraTheme.load();
  await Notifications.init();
  await locateBundledBinaries();
  // Started by Windows at sign-in: come up in the tray, not in the user's face.
  await BackgroundMode.init(startHidden: args.contains(kBackgroundFlag));
  // Being reachable is the point of a messenger, so this is on unless the user
  // turns it off (asked exactly once, on first run).
  await Autostart.enableByDefaultOnce();
  // "Add another account" from the profile menu signs out first, and signing out
  // ends the process — so the request has to arrive as an argument.
  if (args.contains(kNewAccountFlag)) appState.startNewAccountFlow();
  runApp(const UmbraAppRoot());
}

class UmbraAppRoot extends StatelessWidget {
  const UmbraAppRoot({super.key});

  @override
  Widget build(BuildContext context) {
    // The theme sits outermost. The key matters: widgets read their colours
    // from UmbraColors while building, and Flutter skips rebuilding a subtree
    // whose widget instance is unchanged — every `const` widget would keep the
    // colours of the theme it was first built under (white bubbles in a dark
    // theme, a mint accent in the violet one). Changing the key on a theme
    // switch throws the tree away and builds it again with the new palette.
    return ValueListenableBuilder<UmbraPalette>(
      valueListenable: UmbraTheme.notifier,
      builder: (context, palette, _) => MaterialApp(
        key: ValueKey('theme-${palette.id}-${palette.accent.toARGB32()}'),
        title: 'NullChat',
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

/// The NullChat brand mark: a rounded shield with a soft accent glow.
class UmbraMark extends StatelessWidget {
  const UmbraMark({super.key, this.size = 72});
  final double size;

  @override
  Widget build(BuildContext context) {
    // The actual NullChat mark. The artwork already carries its own black
    // ground and rounded corners, so it is drawn as-is rather than dropped
    // inside a tinted tile — the title bar and the tray were showing Ø while
    // the app itself still showed a generic shield glyph.
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(size * 0.22),
        boxShadow: [
          BoxShadow(
            color: UmbraColors.accent.withValues(alpha: 0.18),
            blurRadius: 22,
            spreadRadius: -6,
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(size * 0.22),
        child: Image.asset('assets/logo.png', fit: BoxFit.cover),
      ),
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

  /// How hard the passphrase would be to guess, roughly: 0 (hopeless) to 4.
  ///
  /// This is the only thing standing between a stolen database file and the
  /// messages in it, and an attacker with the file has unlimited attempts, so
  /// the bar is length first — a long ordinary sentence beats a short clever
  /// password.
  int get _strength {
    final p = _pass.text;
    if (p.length < 12) return 0;
    var score = 1;
    if (p.length >= 16) score++;
    if (p.length >= 24) score++;
    final classes = [
      RegExp(r'[a-z]'),
      RegExp(r'[A-Z]'),
      RegExp(r'[0-9]'),
      RegExp(r'[^a-zA-Z0-9]'),
    ].where((r) => r.hasMatch(p)).length;
    if (classes >= 3) score++;
    return score.clamp(0, 4);
  }

  bool get _valid =>
      _username.text.trim().isNotEmpty &&
      _pass.text.length >= 12 &&
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
                Text('NullChat',
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
                  const SizedBox(height: 10),
                  // Strength, plainly: the passphrase is the whole defence for
                  // the database on this disk.
                  Row(
                    children: [
                      Expanded(
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(999),
                          child: LinearProgressIndicator(
                            value: _pass.text.isEmpty ? 0 : (_strength / 4).clamp(0.08, 1.0),
                            minHeight: 5,
                            backgroundColor: UmbraColors.surfaceHigh,
                            color: _strength >= 3
                                ? UmbraColors.accent
                                : _strength >= 1
                                    ? UmbraColors.textMuted
                                    : UmbraColors.danger,
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Text(
                        [
                          L.t('onboard.strength0'),
                          L.t('onboard.strength1'),
                          L.t('onboard.strength2'),
                          L.t('onboard.strength3'),
                          L.t('onboard.strength4'),
                        ][_strength],
                        style: TextStyle(
                            color: _strength >= 3 ? UmbraColors.accent : UmbraColors.textMuted,
                            fontSize: 11),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(L.t('onboard.passHelp'),
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 11, height: 1.35)),
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
                // Offered only where the system can actually hold a passphrase.
                // Elsewhere the switch did nothing, silently.
                if (appState.canRememberPassphrase)
                  CheckboxListTile(
                    value: _remember,
                    onChanged: (v) => setState(() => _remember = v ?? false),
                    controlAffinity: ListTileControlAffinity.leading,
                    contentPadding: EdgeInsets.zero,
                    dense: true,
                    title: Text(L.t('accounts.remember'),
                        style: TextStyle(fontSize: 13, color: UmbraColors.textPrimary)),
                    subtitle: Text(L.t(PassphraseVault.instance.warningKey),
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
  // Where the user is stays in appState, so a theme change (which rebuilds the
  // whole tree) does not throw them back into Chats.
  int get _index => appState.railSection;
  Chat? get _selected => appState.selectedChat;
  GroupChat? get _selectedGroup => appState.selectedGroup;

  /// The middle column: whichever section the rail has selected.
  Widget _section() {
    switch (_index) {
      case 1:
        return const ContactsScreen();
      case 2:
        return const MediaScreen();
      // Devices moved under Settings — it is not a place you visit often.
      case 3:
        return const SettingsScreen();
      default:
        return ChatsScreen(
          selectedHex: _selected?.contactHex,
          // Only one conversation is open at a time, be it a person or a group.
          onSelect: (chat) => setState(() {
            appState.selectedChat = chat;
            appState.selectedGroup = null;
            // No notification for the conversation you are reading.
            Notifications.openConversation = chat.contactHex;
          }),
          selectedGroupHex: _selectedGroup?.idHex,
          onSelectGroup: (group) => setState(() {
            appState.selectedGroup = group;
            appState.selectedChat = null;
            Notifications.openConversation = group.idHex;
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
        onBack: () => setState(() => appState.selectedGroup = null),
        onLeft: () => setState(() => appState.selectedGroup = null),
      );
    }
    if (_selected != null) {
      return ChatDetailScreen(
        key: ValueKey(_selected!.contactHex),
        chat: _selected!,
        embedded: embedded,
        onBack: () => setState(() => appState.selectedChat = null),
      );
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    return UpdateWatcher(
      child: Scaffold(
      body: Column(
        children: [
          // NullChat's own notification. Used when handing one to Windows is not
          // acceptable, because Windows keeps a copy of everything it shows in
          // a database outside this app's reach (see docs/DURESS.md).
          ListenableBuilder(
            listenable: appState,
            builder: (context, _) {
              final notice = appState.inAppNotice;
              return AnimatedSize(
                duration: const Duration(milliseconds: 180),
                curve: Curves.easeOut,
                child: notice == null
                    ? const SizedBox(width: double.infinity)
                    : Container(
                        width: double.infinity,
                        color: UmbraColors.accent.withValues(alpha: 0.14),
                        padding:
                            const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                        child: Row(
                          children: [
                            Icon(Icons.mark_email_unread_outlined,
                                size: 16, color: UmbraColors.accent),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(notice.title,
                                      style: TextStyle(
                                          color: UmbraColors.textPrimary,
                                          fontSize: 12,
                                          fontWeight: FontWeight.w600)),
                                  if (notice.body.isNotEmpty)
                                    Text(notice.body,
                                        maxLines: 2,
                                        overflow: TextOverflow.ellipsis,
                                        style: TextStyle(
                                            color: UmbraColors.textMuted,
                                            fontSize: 12)),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
              );
            },
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
            // Only the top two sections live in the rail's own selection;
            // Settings sits at the bottom with the account, where you look for
            // it rather than pass it on the way to a conversation.
            selectedIndex: _index < 3 ? _index : null,
            onDestinationSelected: (i) => setState(() => appState.railSection = i),
            labelType: NavigationRailLabelType.all,
            leading: const Padding(
              padding: EdgeInsets.symmetric(vertical: 16),
              child: UmbraMark(size: 40),
            ),
            trailing: Expanded(
              child: Align(
                alignment: Alignment.bottomCenter,
                child: Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      _RailButton(
                        icon: Icons.settings_outlined,
                        selectedIcon: Icons.settings,
                        label: L.t('nav.settings'),
                        selected: _index == 2,
                        onTap: () => setState(() => appState.railSection = 3),
                      ),
                      const SizedBox(height: 6),
                      const UpdateRailButton(),
                      const SizedBox(height: 4),
                      const ProfileButton(),
                      const SizedBox(height: 4),
                    ],
                  ),
                ),
              ),
            ),
            destinations: [
              NavigationRailDestination(
                  icon: const Icon(Icons.forum_outlined),
                  selectedIcon: const Icon(Icons.forum),
                  label: Text(L.t('nav.chats'))),
              NavigationRailDestination(
                  icon: const Icon(Icons.contacts_outlined),
                  selectedIcon: const Icon(Icons.contacts),
                  label: Text(L.t('contacts.title'))),
              NavigationRailDestination(
                  icon: const Icon(Icons.perm_media_outlined),
                  selectedIcon: const Icon(Icons.perm_media),
                  label: Text(L.t('media.title'))),
            ],
          );

          // On a phone a side rail eats a fifth of the width and puts the
          // controls where a thumb cannot reach them. Below this width the
          // navigation moves to the bottom, which is also where every other
          // mobile app keeps it.
          final phone = constraints.maxWidth < 600;

          if (phone) {
            final open = _index == 0 ? _conversation(embedded: false) : null;
            return Column(
              children: [
                Expanded(child: open ?? _section()),
                // Hidden while a conversation is open: the keyboard is up, the
                // screen is short, and the way back is the app bar's arrow.
                if (open == null) const _BottomBar(),
              ],
            );
          }

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

/// Navigation for phones: at the bottom, where a thumb reaches.
///
/// Settings does not get an entry of its own here. It lives under the profile,
/// which is where people look for "my stuff" on a phone, and it keeps the bar
/// to three targets — a four-target bar on a narrow screen is how mis-taps
/// happen.
class _BottomBar extends StatelessWidget {
  const _BottomBar();

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final index = appState.railSection;
        return Container(
          decoration: BoxDecoration(
            color: UmbraColors.surface,
            border: Border(top: BorderSide(color: UmbraColors.border)),
          ),
          child: SafeArea(
            top: false,
            child: SizedBox(
              height: 62,
              child: Row(
                children: [
                  _BottomItem(
                    icon: Icons.forum_outlined,
                    selectedIcon: Icons.forum,
                    label: L.t('nav.chats'),
                    selected: index == 0,
                    onTap: () => appState.railSection = 0,
                  ),
                  _BottomItem(
                    icon: Icons.contacts_outlined,
                    selectedIcon: Icons.contacts,
                    label: L.t('contacts.title'),
                    selected: index == 1,
                    onTap: () => appState.railSection = 1,
                  ),
                  _BottomItem(
                    icon: Icons.perm_media_outlined,
                    selectedIcon: Icons.perm_media,
                    label: L.t('media.title'),
                    selected: index == 2,
                    onTap: () => appState.railSection = 2,
                  ),
                  _BottomItem(
                    icon: Icons.person_outline,
                    selectedIcon: Icons.person,
                    label: L.t('nav.profile'),
                    selected: index == 3,
                    onTap: () => appState.railSection = 3,
                    // The one place an update has to be noticeable without
                    // taking a slot in the bar.
                    dot: appState.updateAvailableVersion != null ||
                        appState.updateReadyVersion != null,
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

class _BottomItem extends StatelessWidget {
  const _BottomItem({
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.selected,
    required this.onTap,
    this.dot = false,
  });

  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final bool selected;
  final VoidCallback onTap;
  final bool dot;

  @override
  Widget build(BuildContext context) {
    final color = selected ? UmbraColors.accent : UmbraColors.textMuted;
    return Expanded(
      child: InkWell(
        onTap: onTap,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Stack(
              clipBehavior: Clip.none,
              children: [
                Icon(selected ? selectedIcon : icon, size: 22, color: color),
                if (dot)
                  Positioned(
                    right: -3,
                    top: -2,
                    child: Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                        color: UmbraColors.accent,
                        shape: BoxShape.circle,
                        border: Border.all(color: UmbraColors.surface, width: 1.5),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 3),
            Text(
              label,
              style: TextStyle(
                color: color,
                fontSize: 11,
                fontWeight: selected ? FontWeight.w600 : FontWeight.w400,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// A rail entry that lives outside the NavigationRail's own list (Settings),
/// drawn to match the ones inside it.
class _RailButton extends StatelessWidget {
  const _RailButton({
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final color = selected ? UmbraColors.accent : UmbraColors.textMuted;
    return InkWell(
      borderRadius: BorderRadius.circular(12),
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
              decoration: BoxDecoration(
                color: selected ? UmbraColors.accent.withValues(alpha: 0.13) : null,
                borderRadius: BorderRadius.circular(999),
              ),
              child: Icon(selected ? selectedIcon : icon, size: 22, color: color),
            ),
            const SizedBox(height: 2),
            Text(label,
                style: TextStyle(
                    color: color,
                    fontSize: 12,
                    fontWeight: selected ? FontWeight.w600 : FontWeight.w400)),
          ],
        ),
      ),
    );
  }
}

/// The update button at the bottom of the left bar: a dot when there is
/// something to do, otherwise a quiet check mark.
class UpdateRailButton extends StatelessWidget {
  const UpdateRailButton({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final offered = appState.updateAvailableVersion;
        final ready = appState.updateReadyVersion;
        final busy = appState.updateDownloading;
        final highlight = offered != null || ready != null || busy;
        return Tooltip(
          // No version number here: the bar says whether there is anything to
          // do, and the version itself belongs in Settings.
          message: busy
              ? L.t('update.downloading').replaceAll('{v}', offered ?? '')
              : ready != null
                  ? L.t('update.ready').replaceAll('{v}', ready)
                  : offered != null
                      ? L.t('update.available').replaceAll('{v}', offered)
                      : L.t('update.upToDate'),
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () => showUpdateDialog(context),
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Stack(
                clipBehavior: Clip.none,
                children: [
                  busy
                      ? SizedBox(
                          height: 22,
                          width: 22,
                          child: CircularProgressIndicator(
                              strokeWidth: 2, color: UmbraColors.accent),
                        )
                      : Icon(
                          ready != null
                              ? Icons.system_update_alt
                              : highlight
                                  ? Icons.download_for_offline_outlined
                                  : Icons.verified_outlined,
                          size: 22,
                          color: highlight ? UmbraColors.accent : UmbraColors.textMuted,
                        ),
                  if (highlight && !busy)
                    Positioned(
                      right: -2,
                      top: -2,
                      child: Container(
                        width: 9,
                        height: 9,
                        decoration: BoxDecoration(
                          color: UmbraColors.accent,
                          shape: BoxShape.circle,
                          border: Border.all(color: UmbraColors.surface, width: 1.5),
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

/// Offer the update (or the restart, once it is installed).
void showUpdateDialog(BuildContext context) {
  showDialog<void>(
    context: context,
    // The dialog stays open through the download: it is where the progress is
    // shown, and where the restart is offered when the update lands. Closing it
    // mid-download used to look like nothing had happened.
    builder: (ctx) => ListenableBuilder(
      listenable: appState,
      builder: (ctx, _) {
        final offered = appState.updateAvailableVersion;
        final ready = appState.updateReadyVersion;
        final busy = appState.updateDownloading;
        final error = appState.updateError;
        return AlertDialog(
          backgroundColor: UmbraColors.surfaceHigh,
          title: Text(ready != null
              ? L.t('update.ready').replaceAll('{v}', ready)
              : busy
                  ? L.t('update.workingTitle')
                  : offered != null
                      ? L.t('update.dialogTitle').replaceAll('{v}', offered)
                      : L.t('update.upToDate')),
          content: SizedBox(
            width: 420,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (busy) ...[
                  Row(
                    children: [
                      Expanded(
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(999),
                          child: LinearProgressIndicator(
                            value: appState.updateProgress,
                            minHeight: 6,
                            backgroundColor: UmbraColors.surface,
                          ),
                        ),
                      ),
                      // The plain number out of 100: a bar alone does not say
                      // whether it is nearly done or barely started.
                      if (appState.updatePercent != null) ...[
                        const SizedBox(width: 12),
                        SizedBox(
                          width: 48,
                          child: Text(
                            '${appState.updatePercent} %',
                            textAlign: TextAlign.right,
                            style: TextStyle(
                              color: UmbraColors.accent,
                              fontSize: 14,
                              fontWeight: FontWeight.w700,
                              fontFeatures: const [FontFeature.tabularFigures()],
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                  const SizedBox(height: 10),
                  Text(appState.updateStatus,
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                ] else ...[
                  Text(
                    ready != null || offered != null
                        ? L.t('update.dialogBody')
                        : appState.updateStatus.isEmpty
                            ? L.t('update.checking')
                            : appState.updateStatus,
                    style: TextStyle(color: UmbraColors.textMuted, fontSize: 13, height: 1.4),
                  ),
                  if (offered != null && appState.updateNotes.isNotEmpty) ...[
                    const SizedBox(height: 14),
                    Text(L.t('update.whatsNew'),
                        style: TextStyle(
                            color: UmbraColors.accent,
                            fontSize: 12,
                            fontWeight: FontWeight.w700)),
                    const SizedBox(height: 6),
                    Container(
                      constraints: const BoxConstraints(maxHeight: 220),
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: UmbraColors.surface,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: UmbraColors.border),
                      ),
                      child: SingleChildScrollView(
                        child: Text(appState.updateNotes,
                            style: TextStyle(
                                color: UmbraColors.textPrimary, fontSize: 12, height: 1.45)),
                      ),
                    ),
                  ],
                  if (error != null) ...[
                    const SizedBox(height: 12),
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(Icons.error_outline, size: 16, color: UmbraColors.danger),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(error,
                              style: TextStyle(color: UmbraColors.danger, fontSize: 12, height: 1.35)),
                        ),
                      ],
                    ),
                  ],
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () {
                if (ready == null && offered != null && !busy) appState.postponeUpdate();
                Navigator.pop(ctx);
              },
              child: Text(offered != null || ready != null || busy
                  ? L.t('update.later')
                  : L.t('common.cancel')),
            ),
            if (ready != null)
              FilledButton.icon(
                onPressed: () {
                  Navigator.pop(ctx);
                  appState.restartForUpdate();
                },
                icon: const Icon(Icons.restart_alt, size: 18),
                label: Text(L.t('update.restart')),
              )
            else if (offered != null && !busy)
              FilledButton.icon(
                onPressed: appState.installUpdateNow,
                icon: Icon(error == null ? Icons.download : Icons.refresh, size: 18),
                label: Text(error == null ? L.t('update.install') : L.t('update.retry')),
              ),
          ],
        );
      },
    ),
  );
}

/// Pops the update dialog by itself the moment a new version shows up, so the
/// user does not have to go looking for it.
class UpdateWatcher extends StatefulWidget {
  const UpdateWatcher({super.key, required this.child});
  final Widget child;

  @override
  State<UpdateWatcher> createState() => _UpdateWatcherState();
}

class _UpdateWatcherState extends State<UpdateWatcher> {
  String? _asked;

  @override
  void initState() {
    super.initState();
    appState.addListener(_check);
  }

  @override
  void dispose() {
    appState.removeListener(_check);
    super.dispose();
  }

  void _check() {
    final offered = appState.updateAvailableVersion;
    if (offered == null || offered == _asked || !mounted) return;
    _asked = offered;
    // Wait for the current frame: a dialog cannot open during a build.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && appState.updateAvailableVersion != null) {
        showUpdateDialog(context);
      }
    });
  }

  @override
  Widget build(BuildContext context) => widget.child;
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
