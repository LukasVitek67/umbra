// SPDX-License-Identifier: AGPL-3.0-or-later
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'autostart.dart';
import 'l10n.dart';
import 'duress.dart';
import 'licenses.dart';
import 'notifications.dart';
import 'mock.dart';
import 'screens_chats.dart' show ScreenHeader;
import 'theme.dart';

IconData _platformIcon(String platform) {
  switch (platform) {
    case 'Android':
      return Icons.smartphone;
    case 'Linux':
      return Icons.laptop;
    case 'Windows':
    default:
      return Icons.desktop_windows;
  }
}

class DevicesScreen extends StatelessWidget {
  const DevicesScreen({super.key, this.onBack});

  /// Set when the screen is opened from Settings rather than the rail.
  final VoidCallback? onBack;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final devices = appState.devices;
        final active = devices.where((d) => !d.revoked).length;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ScreenHeader(L.t('devices.title'),
                subtitle: '$active ${L.t('devices.subtitle')}', onBack: onBack),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: Panel(
                child: Row(
                  children: [
                    Icon(Icons.key, color: UmbraColors.accent),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(L.t('devices.fingerprint'),
                              style: const TextStyle(fontWeight: FontWeight.w600)),
                          const SizedBox(height: 3),
                          Text(
                            appState.identityFingerprint,
                            style: TextStyle(
                                fontFamily: 'monospace', color: UmbraColors.textMuted, fontSize: 13),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            Expanded(
              child: ListView.separated(
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
                itemCount: devices.length,
                separatorBuilder: (_, _) => const SizedBox(height: 10),
                itemBuilder: (context, i) => _DeviceTile(device: devices[i]),
              ),
            ),
          ],
        );
      },
    );
  }
}

class _DeviceTile extends StatelessWidget {
  const _DeviceTile({required this.device});
  final Device device;

  @override
  Widget build(BuildContext context) {
    final revoked = device.revoked;
    return Opacity(
      opacity: revoked ? 0.5 : 1,
      child: Panel(
        child: Row(
          children: [
            Icon(_platformIcon(device.platform),
                color: revoked ? UmbraColors.textMuted : UmbraColors.accent),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(device.name, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
                      const SizedBox(width: 8),
                      if (device.current) Pill(L.t('devices.thisDevice')),
                      if (revoked)
                        Pill(L.t('devices.revoked'), color: UmbraColors.danger, icon: Icons.block),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text('${device.platform} • ${L.t('devices.lastSeen')} ${device.lastSeen}',
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
                  const SizedBox(height: 2),
                  Text(device.fingerprint,
                      style: TextStyle(
                          fontFamily: 'monospace', color: UmbraColors.textMuted, fontSize: 11)),
                ],
              ),
            ),
            if (!device.current && !revoked)
              IconButton(
                tooltip: L.t('devices.revoke'),
                icon: Icon(Icons.block, color: UmbraColors.danger),
                onPressed: () => _confirmRevoke(context, device),
              ),
          ],
        ),
      ),
    );
  }

  void _confirmRevoke(BuildContext context, Device device) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: UmbraColors.surfaceHigh,
        title: Text(L.t('devices.revokeTitle')),
        content: Text(
          '„${device.name}" — ${L.t('devices.revokeBody')}',
          style: TextStyle(color: UmbraColors.textMuted),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: Text(L.t('common.cancel'))),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: UmbraColors.danger),
            onPressed: () {
              appState.revokeDevice(device);
              Navigator.pop(ctx);
            },
            child: Text(L.t('devices.revoke')),
          ),
        ],
      ),
    );
  }
}

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        return ListView(
          children: [
            ScreenHeader(L.t('settings.title')),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: Panel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        _MyAvatar(),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('@${appState.username}',
                                  style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                              const SizedBox(height: 2),
                              Text(L.t('settings.yourCode'),
                                  style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
                              const SizedBox(height: 4),
                              TextButton.icon(
                                onPressed: () async {
                                  final r = await FilePicker.pickFiles(
                                    type: FileType.image,
                                    withData: true,
                                  );
                                  final bytes = r?.files.single.bytes;
                                  if (bytes != null) appState.setMyPicture(bytes);
                                },
                                icon: const Icon(Icons.photo_camera_outlined, size: 15),
                                label: Text(L.t('settings.pickPicture')),
                                style: TextButton.styleFrom(
                                  padding: EdgeInsets.zero,
                                  minimumSize: const Size(0, 28),
                                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 14),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      decoration: BoxDecoration(
                        color: UmbraColors.surfaceHigh,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: UmbraColors.border),
                      ),
                      child: Row(
                        children: [
                          Icon(Icons.tag, size: 18, color: UmbraColors.accent),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              appState.userCode,
                              style: TextStyle(
                                  fontFamily: 'monospace',
                                  fontSize: 15,
                                  fontWeight: FontWeight.w600,
                                  color: UmbraColors.accent),
                            ),
                          ),
                          IconButton(
                            tooltip: L.t('settings.copyCode'),
                            icon: Icon(Icons.copy, size: 18, color: UmbraColors.textMuted),
                            onPressed: () {
                              Clipboard.setData(ClipboardData(text: appState.userCode));
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text(L.t('settings.codeCopied'))),
                              );
                            },
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 10),
                    SizedBox(
                      width: double.infinity,
                      child: OutlinedButton.icon(
                        onPressed: appState.torConnected
                            ? () {
                                Clipboard.setData(ClipboardData(text: appState.myInvite()));
                                ScaffoldMessenger.of(context).showSnackBar(
                                  SnackBar(
                                      content: Text(L.t('settings.inviteCopied'))),
                                );
                              }
                            : null,
                        icon: const Icon(Icons.ios_share, size: 18),
                        label: Text(appState.torConnected
                            ? L.t('settings.copyInvite')
                            : L.t('settings.inviteNotReady')),
                        style: OutlinedButton.styleFrom(
                          foregroundColor: UmbraColors.accent,
                          side: BorderSide(color: UmbraColors.border),
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: Panel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.hub,
                            color: appState.torConnected
                                ? UmbraColors.accent
                                : UmbraColors.textMuted),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(L.t('settings.network'),
                                  style: const TextStyle(fontWeight: FontWeight.w600)),
                              const SizedBox(height: 3),
                              Text(
                                appState.netStatus,
                                style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                              ),
                            ],
                          ),
                        ),
                        if (appState.isConnecting)
                          const SizedBox(
                            height: 16,
                            width: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        else
                          Pill(appState.torConnected ? L.t('settings.online') : L.t('settings.offline'),
                              color: appState.torConnected
                                  ? UmbraColors.accent
                                  : UmbraColors.textMuted),
                      ],
                    ),
                    if (appState.onion.isNotEmpty) ...[
                      const SizedBox(height: 12),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        decoration: BoxDecoration(
                          color: UmbraColors.surfaceHigh,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: UmbraColors.border),
                        ),
                        child: Row(
                          children: [
                            Icon(Icons.alternate_email,
                                size: 16, color: UmbraColors.textMuted),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                appState.onion,
                                style: TextStyle(
                                    fontFamily: 'monospace',
                                    fontSize: 11,
                                    color: UmbraColors.textMuted),
                              ),
                            ),
                            IconButton(
                              tooltip: L.t('settings.copyOnion'),
                              icon: Icon(Icons.copy, size: 16, color: UmbraColors.textMuted),
                              onPressed: () {
                                Clipboard.setData(ClipboardData(text: appState.onion));
                                ScaffoldMessenger.of(context).showSnackBar(
                                  SnackBar(content: Text(L.t('settings.onionCopied'))),
                                );
                              },
                            ),
                          ],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: _DevicesEntry(),
            ),
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: _BridgesPanel(),
            ),
            if (Autostart.supported)
              const Padding(
                padding: EdgeInsets.symmetric(horizontal: 24, vertical: 8),
                child: _AutostartPanel(),
              ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: Panel(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(L.t('settings.padding'), style: const TextStyle(fontWeight: FontWeight.w600)),
                    const SizedBox(height: 4),
                    Text(
                      L.t('settings.paddingHelp'),
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                    ),
                    const SizedBox(height: 12),
                    Wrap(
                      spacing: 8,
                      children: List.generate(kPaddingBuckets.length, (i) {
                        final selected = appState.paddingFloorIndex == i;
                        final label =
                            kPaddingBuckets[i] >= 1024 ? '${kPaddingBuckets[i] ~/ 1024} KB' : '${kPaddingBuckets[i]} B';
                        return ChoiceChip(
                          label: Text(label),
                          selected: selected,
                          onSelected: (_) => appState.setPaddingFloor(i),
                          backgroundColor: UmbraColors.surfaceHigh,
                          selectedColor: UmbraColors.accent.withValues(alpha: 0.2),
                          labelStyle: TextStyle(
                              color: selected ? UmbraColors.accent : UmbraColors.textMuted,
                              fontWeight: FontWeight.w600),
                          side: BorderSide(
                              color: selected ? UmbraColors.accent : UmbraColors.border),
                        );
                      }),
                    ),
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: _ThemePanel(),
            ),
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: _NotificationsPanel(),
            ),
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: _UpdatePanel(),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: _DuressEntry(),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: _LicensesEntry(),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: Panel(
                child: Row(
                  children: [
                    Icon(Icons.language, color: UmbraColors.textMuted),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Text(L.t('settings.language'),
                          style: const TextStyle(fontWeight: FontWeight.w600)),
                    ),
                    SegmentedButton<String>(
                      segments: [
                        const ButtonSegment(value: 'en', label: Text('English')),
                        const ButtonSegment(value: 'cs', label: Text('Čeština')),
                      ],
                      selected: {L.lang},
                      showSelectedIcon: false,
                      onSelectionChanged: (sel) => L.set(sel.first),
                      style: ButtonStyle(
                        textStyle: WidgetStateProperty.all(const TextStyle(fontSize: 12)),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: Panel(
                child: Row(
                  children: [
                    Icon(Icons.info_outline, color: UmbraColors.textMuted),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Text(
                        L.t('settings.disclaimer'),
                        style: TextStyle(color: UmbraColors.textMuted, fontSize: 13, height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        );
      },
    );
  }
}


/// Your own Tor bridges.
///
/// The bridges NullChat ships are public, which means a censor can — and usually
/// does — have them on a list. Anyone actually behind such a censor needs lines
/// from bridges.torproject.org, and those are personal, so they belong here
/// rather than in the build.
class _BridgesPanel extends StatefulWidget {
  const _BridgesPanel();

  @override
  State<_BridgesPanel> createState() => _BridgesPanelState();
}

class _BridgesPanelState extends State<_BridgesPanel> {
  final _controller = TextEditingController();
  bool _open = false;
  bool _saved = false;

  @override
  void initState() {
    super.initState();
    _controller.text = appState.customBridges;
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final using = _controller.text.trim().isNotEmpty;
    return Panel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          InkWell(
            onTap: () => setState(() => _open = !_open),
            child: Row(
              children: [
                Icon(Icons.alt_route, color: using ? UmbraColors.accent : UmbraColors.textMuted),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(L.t('bridges.title'),
                          style: const TextStyle(fontWeight: FontWeight.w600)),
                      const SizedBox(height: 3),
                      Text(using ? L.t('bridges.usingCustom') : L.t('bridges.usingDefault'),
                          style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                    ],
                  ),
                ),
                Icon(_open ? Icons.expand_less : Icons.expand_more, color: UmbraColors.textMuted),
              ],
            ),
          ),
          if (_open) ...[
            const SizedBox(height: 12),
            Text(L.t('bridges.help'),
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 12, height: 1.4)),
            const SizedBox(height: 10),
            TextField(
              controller: _controller,
              minLines: 3,
              maxLines: 8,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: InputDecoration(hintText: L.t('bridges.hint')),
              onChanged: (_) => setState(() => _saved = false),
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                FilledButton.icon(
                  onPressed: () {
                    appState.setCustomBridges(_controller.text);
                    setState(() => _saved = true);
                  },
                  icon: const Icon(Icons.save_outlined, size: 18),
                  label: Text(L.t('common.save')),
                ),
                const SizedBox(width: 12),
                if (_saved)
                  Expanded(
                    child: Text(L.t('bridges.saved'),
                        style: TextStyle(color: UmbraColors.accent, fontSize: 12)),
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

/// How much a notification is allowed to say.
///
/// The detailed form is tied to auto sign-in on purpose: it is the same
/// decision, stated twice. If this computer may open the account unattended,
/// showing the message on it changes nothing; if it may not, the notification
/// must not become the back door.
class _NotificationsPanel extends StatefulWidget {
  const _NotificationsPanel();

  @override
  State<_NotificationsPanel> createState() => _NotificationsPanelState();
}

class _NotificationsPanelState extends State<_NotificationsPanel> {
  @override
  Widget build(BuildContext context) {
    final allowed = appState.autologinEnabled;
    return Panel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.notifications_none, color: UmbraColors.textMuted),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(L.t('notif.detail'),
                        style: TextStyle(
                            fontWeight: FontWeight.w600,
                            color: allowed ? UmbraColors.textPrimary : UmbraColors.textMuted)),
                    const SizedBox(height: 3),
                    Text(
                      allowed ? L.t('notif.detailHelp') : L.t('notif.detailLocked'),
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 13, height: 1.35),
                    ),
                  ],
                ),
              ),
              Switch(
                value: allowed && Notifications.showContent,
                onChanged: allowed
                    ? (v) async {
                        await Notifications.setShowContent(v);
                        if (mounted) setState(() {});
                      }
                    : null,
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            L
                .t('notif.example')
                .replaceAll('{account}', appState.username)
                .replaceAll(
                  '{example}',
                  allowed && Notifications.showContent
                      ? '${L.t('notif.exampleFrom')} → @${appState.username}: ${L.t('notif.exampleBody')}'
                      : L.t('notif.newFor').replaceAll('{account}', appState.username),
                ),
            style: TextStyle(color: UmbraColors.textMuted, fontSize: 12, fontStyle: FontStyle.italic),
          ),
        ],
      ),
    );
  }
}

/// A second (or third) way into this account that does something else.
class _DuressEntry extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final set = appState.duressConfigured;
        return InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () => showDuressScreen(context),
          child: Panel(
            child: Row(
              children: [
                Icon(Icons.shield_outlined, color: UmbraColors.textMuted),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(L.t('duress.title'),
                          style: const TextStyle(fontWeight: FontWeight.w600)),
                      const SizedBox(height: 3),
                      Text(
                        set.isEmpty
                            ? L.t('duress.none')
                            : L.t('duress.count')
                                .replaceAll('{n}', set.length.toString()),
                        style: TextStyle(
                            color: set.isEmpty
                                ? UmbraColors.textMuted
                                : UmbraColors.accent,
                            fontSize: 13),
                      ),
                    ],
                  ),
                ),
                Icon(Icons.chevron_right, color: UmbraColors.textMuted),
              ],
            ),
          ),
        );
      },
    );
  }
}

/// What NullChat is built from, and under what licence.
class _LicensesEntry extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(16),
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (ctx) => Scaffold(
            body: SafeArea(child: LicensesScreen(onBack: () => Navigator.of(ctx).pop())),
          ),
        ),
      ),
      child: Panel(
        child: Row(
          children: [
            Icon(Icons.balance, color: UmbraColors.textMuted),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(L.t('licenses.title'),
                      style: const TextStyle(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 3),
                  Text(L.t('licenses.subtitle'),
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: UmbraColors.textMuted),
          ],
        ),
      ),
    );
  }
}

/// The full list: what we ship, what we link against, and the terms.
class LicensesScreen extends StatelessWidget {
  const LicensesScreen({super.key, this.onBack});
  final VoidCallback? onBack;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ScreenHeader(L.t('licenses.title'),
            subtitle: L.t('licenses.header'), onBack: onBack),
        Expanded(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
            children: [
              for (final section in kLicenses) ...[
                Padding(
                  padding: const EdgeInsets.fromLTRB(4, 14, 4, 8),
                  child: Text(section.title,
                      style: TextStyle(
                          color: UmbraColors.accent,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.4)),
                ),
                for (final e in section.entries)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 10),
                    child: Panel(
                      padding: const EdgeInsets.all(14),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Expanded(
                                child: Text(e.name,
                                    style: const TextStyle(
                                        fontWeight: FontWeight.w600, fontSize: 14)),
                              ),
                              const SizedBox(width: 10),
                              Pill(e.license),
                            ],
                          ),
                          const SizedBox(height: 6),
                          Text(e.what,
                              style: TextStyle(
                                  color: UmbraColors.textMuted, fontSize: 13, height: 1.35)),
                          if (e.url != null) ...[
                            const SizedBox(height: 6),
                            SelectableText(e.url!,
                                style: TextStyle(
                                    color: UmbraColors.textMuted,
                                    fontSize: 11,
                                    fontFamily: 'monospace')),
                          ],
                        ],
                      ),
                    ),
                  ),
              ],
              const SizedBox(height: 8),
              Text(L.t('licenses.full'),
                  style: TextStyle(color: UmbraColors.textMuted, fontSize: 12, height: 1.4)),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: () => showLicensePage(
                  context: context,
                  applicationName: 'NullChat',
                  applicationVersion: appState.version,
                  applicationLegalese: 'AGPL-3.0-or-later',
                ),
                icon: const Icon(Icons.article_outlined, size: 18),
                label: Text(L.t('licenses.packages')),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

/// Devices used to be its own rail section; it is rare enough to live in
/// Settings and open on demand.
class _DevicesEntry extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final active = appState.devices.where((d) => !d.revoked).length;
    return InkWell(
      borderRadius: BorderRadius.circular(16),
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (ctx) => Scaffold(
            body: SafeArea(
              child: DevicesScreen(onBack: () => Navigator.of(ctx).pop()),
            ),
          ),
        ),
      ),
      child: Panel(
        child: Row(
          children: [
            Icon(Icons.devices, color: UmbraColors.textMuted),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(L.t('devices.title'),
                      style: const TextStyle(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 3),
                  Text('$active ${L.t('devices.subtitle')}',
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: UmbraColors.textMuted),
          ],
        ),
      ),
    );
  }
}

/// Start with Windows. The switch reflects the registry, not our wish: if the
/// write fails the toggle snaps back instead of lying to the user.
class _AutostartPanel extends StatefulWidget {
  const _AutostartPanel();

  @override
  State<_AutostartPanel> createState() => _AutostartPanelState();
}

class _AutostartPanelState extends State<_AutostartPanel> {
  bool? _on;

  @override
  void initState() {
    super.initState();
    Autostart.isEnabled().then((v) {
      if (mounted) setState(() => _on = v);
    });
  }

  Future<void> _toggle(bool want) async {
    setState(() => _on = want);
    final ok = await Autostart.set(want);
    final actual = await Autostart.isEnabled();
    if (!mounted) return;
    setState(() => _on = actual);
    if (!ok || actual != want) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(L.t('settings.autostartFailed'))),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Panel(
      child: Row(
        children: [
          Icon(Icons.power_settings_new, color: UmbraColors.textMuted),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(L.t('settings.autostart'),
                    style: const TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 3),
                Text(L.t('settings.autostartHelp'),
                    style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                const SizedBox(height: 4),
                Text(L.t('settings.trayHint'),
                    style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
              ],
            ),
          ),
          Switch(
            value: _on ?? false,
            onChanged: _on == null ? null : _toggle,
          ),
        ],
      ),
    );
  }
}

/// Version and update state. The check itself runs in Rust, through Tor, and
/// installs nothing that is not signed with the author's key.
class _UpdatePanel extends StatelessWidget {
  const _UpdatePanel();

  @override
  Widget build(BuildContext context) {
    final ready = appState.updateReadyVersion;
    return Panel(
      child: Row(
        children: [
          Icon(ready == null ? Icons.verified_outlined : Icons.system_update_alt,
              color: ready == null ? UmbraColors.textMuted : UmbraColors.accent),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('${L.t('update.title')} ${appState.version}',
                    style: const TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 3),
                Text(
                  appState.updateStatus.isEmpty
                      ? L.t('update.checking')
                      : appState.updateStatus,
                  style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                ),
              ],
            ),
          ),
          if (ready != null)
            FilledButton.icon(
              onPressed: appState.restartForUpdate,
              icon: const Icon(Icons.restart_alt, size: 18),
              label: Text(L.t('update.restart')),
            ),
        ],
      ),
    );
  }
}

/// Theme picker: the built-in palettes plus a colour the user mixes themselves.
class _ThemePanel extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<UmbraPalette>(
      valueListenable: UmbraTheme.notifier,
      builder: (context, active, _) => Panel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.palette_outlined, color: UmbraColors.textMuted),
                const SizedBox(width: 14),
                Text(L.t('settings.theme'),
                    style: const TextStyle(fontWeight: FontWeight.w600)),
              ],
            ),
            const SizedBox(height: 4),
            Text(L.t('settings.themeHelp'),
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
            const SizedBox(height: 14),
            Wrap(
              spacing: 14,
              runSpacing: 12,
              children: [
                for (final p in UmbraPalettes.all)
                  _Swatch(
                    label: L.t('theme.${p.id}'),
                    color: p.accent,
                    ring: p.dark ? p.surfaceHigh : p.border,
                    selected: active.id == p.id,
                    onTap: () => UmbraTheme.set(p),
                  ),
                _Swatch(
                  label: L.t('theme.custom'),
                  color: active.id == 'custom' ? active.accent : null,
                  ring: UmbraColors.border,
                  selected: active.id == 'custom',
                  onTap: () => showDialog<void>(
                    context: context,
                    builder: (_) => _CustomColorDialog(start: active.accent),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// One theme dot. Without a colour it shows the full spectrum (the "mix your
/// own" entry).
class _Swatch extends StatelessWidget {
  const _Swatch({
    required this.label,
    required this.color,
    required this.ring,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final Color? color;
  final Color ring;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(12),
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 34,
              height: 34,
              decoration: BoxDecoration(
                color: color,
                gradient: color == null
                    ? SweepGradient(
                        colors: [
                          for (double h = 0; h <= 360; h += 60)
                            HSLColor.fromAHSL(1, h % 360, 0.75, 0.6).toColor(),
                        ],
                      )
                    : null,
                shape: BoxShape.circle,
                border: Border.all(
                  color: selected ? UmbraColors.textPrimary : ring,
                  width: selected ? 2.5 : 1,
                ),
              ),
              child: selected
                  ? Icon(Icons.check, size: 18, color: UmbraColors.accentInk)
                  : null,
            ),
            const SizedBox(height: 5),
            Text(label,
                style: TextStyle(
                    fontSize: 11,
                    color: selected ? UmbraColors.textPrimary : UmbraColors.textMuted,
                    fontWeight: selected ? FontWeight.w600 : FontWeight.w400)),
          ],
        ),
      ),
    );
  }
}

/// Mixes a custom accent: hue and intensity, with a live preview of the
/// surfaces the accent will be sitting on.
class _CustomColorDialog extends StatefulWidget {
  const _CustomColorDialog({required this.start});
  final Color start;

  @override
  State<_CustomColorDialog> createState() => _CustomColorDialogState();
}

class _CustomColorDialogState extends State<_CustomColorDialog> {
  late double _hue;
  late double _saturation;

  @override
  void initState() {
    super.initState();
    final hsl = HSLColor.fromColor(widget.start);
    _hue = hsl.hue;
    _saturation = hsl.saturation.clamp(0.35, 1.0);
  }

  Color get _color => HSLColor.fromAHSL(1, _hue, _saturation, 0.62).toColor();

  @override
  Widget build(BuildContext context) {
    final preview = UmbraPalette.fromAccent(_color);
    return AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('settings.themeCustomTitle')),
      content: SizedBox(
        width: 340,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(L.t('settings.themeHue'),
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
            const SizedBox(height: 8),
            _HueBar(hue: _hue, onChanged: (h) => setState(() => _hue = h)),
            const SizedBox(height: 16),
            Text(L.t('settings.themeSaturation'),
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
            Slider(
              value: _saturation,
              min: 0.35,
              max: 1.0,
              activeColor: _color,
              onChanged: (v) => setState(() => _saturation = v),
            ),
            const SizedBox(height: 8),
            // The preview shows the derived surfaces, not just the accent —
            // that is what the whole app will look like.
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: preview.bg,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: preview.border),
              ),
              child: Row(
                children: [
                  Container(
                    width: 28,
                    height: 28,
                    decoration: BoxDecoration(color: preview.accent, shape: BoxShape.circle),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(L.t('settings.themePreview'),
                            style: TextStyle(
                                color: preview.textPrimary,
                                fontSize: 13,
                                fontWeight: FontWeight.w600)),
                        const SizedBox(height: 2),
                        Text('#${_color.toARGB32().toRadixString(16).substring(2).toUpperCase()}',
                            style: TextStyle(
                                color: preview.textMuted,
                                fontFamily: 'monospace',
                                fontSize: 11)),
                      ],
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                    decoration: BoxDecoration(
                      color: preview.accent.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(999),
                      border: Border.all(color: preview.accent.withValues(alpha: 0.35)),
                    ),
                    child: Text('Tor',
                        style: TextStyle(
                            color: preview.accent, fontSize: 12, fontWeight: FontWeight.w600)),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(L.t('common.cancel'))),
        FilledButton(
          onPressed: () {
            UmbraTheme.setCustomAccent(_color);
            Navigator.pop(context);
          },
          child: Text(L.t('settings.themeCustom')),
        ),
      ],
    );
  }
}

/// A draggable rainbow strip — a full colour wheel would be overkill for one
/// accent colour.
class _HueBar extends StatelessWidget {
  const _HueBar({required this.hue, required this.onChanged});
  final double hue;
  final ValueChanged<double> onChanged;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, c) {
        void pick(Offset local) =>
            onChanged(((local.dx / c.maxWidth).clamp(0.0, 1.0)) * 359.9);
        return GestureDetector(
          onTapDown: (d) => pick(d.localPosition),
          onHorizontalDragUpdate: (d) => pick(d.localPosition),
          child: SizedBox(
            height: 30,
            child: Stack(
              clipBehavior: Clip.none,
              children: [
                Container(
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(999),
                    gradient: LinearGradient(
                      colors: [
                        for (double h = 0; h <= 360; h += 30)
                          HSLColor.fromAHSL(1, h % 360, 0.75, 0.6).toColor(),
                      ],
                    ),
                  ),
                ),
                Positioned(
                  left: (hue / 360 * c.maxWidth).clamp(0.0, c.maxWidth - 22),
                  top: 3,
                  child: Container(
                    width: 22,
                    height: 24,
                    decoration: BoxDecoration(
                      color: HSLColor.fromAHSL(1, hue, 0.75, 0.6).toColor(),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.white, width: 2.5),
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

/// Our own avatar: the picture we set, or the first letter of our username.
class _MyAvatar extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final bytes = appState.myPicture();
    if (bytes.isNotEmpty) {
      return CircleAvatar(
        radius: 24,
        backgroundColor: UmbraColors.surfaceHigh,
        backgroundImage: MemoryImage(bytes),
      );
    }
    return CircleAvatar(
      radius: 24,
      backgroundColor: UmbraColors.surfaceHigh,
      child: Text(
        appState.username.isEmpty ? '?' : appState.username.substring(0, 1).toUpperCase(),
        style: TextStyle(
            color: UmbraColors.accent, fontWeight: FontWeight.w700, fontSize: 18),
      ),
    );
  }
}
