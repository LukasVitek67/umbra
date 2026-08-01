// SPDX-License-Identifier: AGPL-3.0-or-later
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'gif_picker.dart';
import 'attachment_preview.dart';
import 'l10n.dart';
import 'message_menu.dart';
import 'mock.dart';
import 'src/rust/api/nullchat.dart' show SearchHitView;
import 'theme.dart';

String _hhmm(DateTime t) =>
    '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';

/// Confirm before removing a contact and its history.
///
/// Asked rather than done, because this is the one action in the app that
/// destroys the user's own data, and there is no undo: the messages are gone
/// from the encrypted store, not moved to a bin.
Future<void> showDeleteChat(BuildContext context, Chat chat) async {
  final count = chat.messages.length;
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('contacts.delete')),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              L
                  .t('contacts.deleteBody')
                  .replaceAll('{name}', chat.name)
                  .replaceAll('{n}', count.toString()),
              style: TextStyle(
                  color: UmbraColors.textMuted, fontSize: 13, height: 1.45),
            ),
            const SizedBox(height: 12),
            Text(chat.userCode,
                style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: UmbraColors.textMuted)),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(false),
          child: Text(L.t('common.cancel')),
        ),
        FilledButton(
          style: FilledButton.styleFrom(backgroundColor: UmbraColors.danger),
          onPressed: () => Navigator.of(ctx).pop(true),
          child: Text(L.t('contacts.delete')),
        ),
      ],
    ),
  );
  if (confirmed == true) {
    appState.deleteChat(chat);
  }
}

/// Pick the conversation this one should be folded into.
///
/// Two identities are two identities as far as the app is concerned; the person
/// on the other side is something only the user knows. So this asks, showing
/// each candidate's own code, rather than pairing anybody up by display name —
/// two people who share a name are not one person.
Future<void> showMergeDialog(BuildContext context, Chat chat) async {
  final others = appState.chats.where((c) => c.contactHex != chat.contactHex).toList();
  if (others.isEmpty) return;

  final target = await showDialog<Chat>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('merge.title').replaceAll('{name}', chat.name)),
      content: SizedBox(
        width: 460,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              L.t('merge.body').replaceAll('{name}', chat.name),
              style: TextStyle(
                  color: UmbraColors.textMuted, fontSize: 13, height: 1.45),
            ),
            const SizedBox(height: 14),
            Flexible(
              child: ListView(
                shrinkWrap: true,
                children: [
                  for (final other in others)
                    ListTile(
                      dense: true,
                      title: Text(other.name),
                      subtitle: Text(
                        '${other.userCode}  ·  ${other.messages.length}',
                        style: TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 11,
                            color: UmbraColors.textMuted),
                      ),
                      onTap: () => Navigator.of(ctx).pop(other),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(),
          child: Text(L.t('common.cancel')),
        ),
      ],
    ),
  );
  if (target != null) {
    appState.mergeChats(chat, target);
  }
}

/// Show the safety number and let the user say whether it matched.
///
/// This is the only check in NullChat that needs a person. Everything else proves
/// that the other end holds the key named in the invite; only this proves the
/// invite was theirs. So the dialog says what to do and why, in words — a
/// screen of digits with a tick box would get ticked without being read.
void showSafetyNumberDialog(BuildContext context, Chat chat) {
  final number = appState.safetyNumber(chat.contactHex);
  final postQuantum = appState.contactIsPostQuantum(chat.contactHex);
  showDialog<void>(
    context: context,
    builder: (ctx) => ListenableBuilder(
      listenable: appState,
      builder: (ctx, _) => AlertDialog(
        backgroundColor: UmbraColors.surfaceHigh,
        title: Text(L.t('safety.title').replaceAll('{name}', chat.name)),
        content: SizedBox(
          width: 460,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                L.t('safety.how'),
                style: TextStyle(
                    color: UmbraColors.textMuted, fontSize: 13, height: 1.45),
              ),
              const SizedBox(height: 16),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                decoration: BoxDecoration(
                  color: UmbraColors.surface,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: UmbraColors.border),
                ),
                child: SelectableText(
                  number,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 17,
                    height: 1.8,
                    letterSpacing: 1.5,
                    fontFeatures: [FontFeature.tabularFigures()],
                  ),
                ),
              ),
              const SizedBox(height: 14),
              // Which schemes this identity is signed under. Said plainly,
              // because "post-quantum" is worth nothing if the contact predates
              // it and the app lets you assume otherwise.
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(postQuantum ? Icons.shield_moon_rounded : Icons.shield_outlined,
                      size: 16,
                      color: postQuantum ? UmbraColors.accent : UmbraColors.textMuted),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      postQuantum ? L.t('safety.pq') : L.t('safety.noPq'),
                      style: TextStyle(
                          color: UmbraColors.textMuted, fontSize: 12, height: 1.4),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    chat.verified ? Icons.verified_user : Icons.info_outline,
                    size: 16,
                    color: chat.verified ? UmbraColors.accent : UmbraColors.textMuted,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      chat.verified ? L.t('safety.isVerified') : L.t('safety.warning'),
                      style: TextStyle(
                        color: chat.verified ? UmbraColors.accent : UmbraColors.textMuted,
                        fontSize: 12,
                        height: 1.4,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: Text(L.t('common.close')),
          ),
          if (chat.verified)
            TextButton(
              onPressed: () => appState.setVerified(chat, false),
              child: Text(L.t('safety.unverify'),
                  style: TextStyle(color: UmbraColors.danger)),
            )
          else
            FilledButton.icon(
              onPressed: () => appState.setVerified(chat, true),
              icon: const Icon(Icons.check, size: 18),
              label: Text(L.t('safety.confirm')),
            ),
        ],
      ),
    ),
  );
}

void showAddContact(BuildContext context) {
  showDialog<void>(
    context: context,
    builder: (ctx) => const _AddContactDialog(),
  );
}

class _AddContactDialog extends StatefulWidget {
  const _AddContactDialog();

  @override
  State<_AddContactDialog> createState() => _AddContactDialogState();
}

class _AddContactDialogState extends State<_AddContactDialog> {
  final _controller = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null) {
      _controller.text = data!.text!.trim();
      setState(() => _error = null);
    }
  }

  void _submit() {
    final text = _controller.text.trim();
    if (!text.startsWith('umbra1:')) {
      setState(() => _error =
L.t('add.notInvite'));
      return;
    }
    if (appState.addContactByCode(text)) {
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(L.t('add.ok'))),
      );
    } else {
      setState(() => _error = appState.lastError ?? L.t('add.failed'));
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('add.title')),
      content: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 460),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              L.t('add.help'),
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 13, height: 1.4),
            ),
            const SizedBox(height: 6),
            Text(
              L.t('add.help2'),
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 12, height: 1.35),
            ),
            const SizedBox(height: 14),
            TextField(
              controller: _controller,
              autofocus: true,
              maxLines: 3,
              minLines: 2,
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
              onChanged: (_) {
                if (_error != null) setState(() => _error = null);
              },
              decoration: const InputDecoration(hintText: 'umbra1:…'),
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                onPressed: _paste,
                icon: const Icon(Icons.content_paste, size: 16),
                label: Text(L.t('add.paste')),
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 4),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: UmbraColors.danger.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: UmbraColors.danger.withValues(alpha: 0.4)),
                ),
                child: Text(
                  _error!,
                  style: TextStyle(color: UmbraColors.danger, fontSize: 12, height: 1.35),
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(L.t('add.cancel'))),
        FilledButton(onPressed: _submit, child: Text(L.t('add.submit'))),
      ],
    );
  }
}

class ScreenHeader extends StatelessWidget {
  const ScreenHeader(this.title, {super.key, this.subtitle, this.trailing, this.onBack});
  final String title;
  final String? subtitle;
  final Widget? trailing;

  /// Shown as a back arrow on screens opened from another one.
  final VoidCallback? onBack;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.fromLTRB(onBack == null ? 24 : 8, 24, 24, 12),
      child: Row(
        children: [
          if (onBack != null)
            IconButton(
              icon: const Icon(Icons.arrow_back),
              color: UmbraColors.textMuted,
              onPressed: onBack,
            ),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontSize: 26)),
                if (subtitle != null) ...[
                  const SizedBox(height: 2),
                  Text(subtitle!, style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                ],
              ],
            ),
          ),
          ?trailing,
        ],
      ),
    );
  }
}

class ChatsScreen extends StatefulWidget {
  const ChatsScreen({
    super.key,
    this.onSelect,
    this.selectedHex,
    this.onSelectGroup,
    this.selectedGroupHex,
  });

  /// Called when a conversation is picked (split view puts it on the right).
  final void Function(Chat chat)? onSelect;
  final String? selectedHex;

  /// The same, for group conversations.
  final void Function(GroupChat group)? onSelectGroup;
  final String? selectedGroupHex;

  @override
  State<ChatsScreen> createState() => _ChatsScreenState();
}

class _ChatsScreenState extends State<ChatsScreen> {
  final _search = TextEditingController();
  String _query = '';

  void Function(Chat chat)? get onSelect => widget.onSelect;
  String? get selectedHex => widget.selectedHex;
  void Function(GroupChat group)? get onSelectGroup => widget.onSelectGroup;
  String? get selectedGroupHex => widget.selectedGroupHex;

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        // Blocked contacts are gone from here; people who wrote to us first
        // wait in their own section until the user decides.
        final chats = appState.openChats;
        final groups = appState.groups;
        final waiting = appState.waitingChats;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ScreenHeader(
              L.t('chats.title'),
              subtitle: L.t('chats.subtitle'),
              // One button, two ways to start something: a group, or a person
              // from their invite.
              trailing: PopupMenuButton<String>(
                tooltip: L.t('chats.new'),
                position: PopupMenuPosition.under,
                onSelected: (value) {
                  if (value == 'group') {
                    showCreateGroup(context);
                  } else {
                    showAddContact(context);
                  }
                },
                itemBuilder: (context) => [
                  PopupMenuItem(
                    value: 'contact',
                    child: Row(children: [
                      Icon(Icons.person_add_alt_1, size: 18, color: UmbraColors.textMuted),
                      const SizedBox(width: 10),
                      Text(L.t('chats.add')),
                    ]),
                  ),
                  PopupMenuItem(
                    value: 'group',
                    child: Row(children: [
                      Icon(Icons.group_add_outlined, size: 18, color: UmbraColors.textMuted),
                      const SizedBox(width: 10),
                      Text(L.t('groups.create')),
                    ]),
                  ),
                ],
                child: FilledButton.icon(
                  // The menu is on the parent; the button only has to look like
                  // one, hence the null callback.
                  onPressed: null,
                  icon: const Icon(Icons.add, size: 18),
                  label: Text(L.t('chats.new')),
                  style: FilledButton.styleFrom(
                    backgroundColor: UmbraColors.accent,
                    disabledBackgroundColor: UmbraColors.accent,
                    foregroundColor: UmbraColors.accentInk,
                    disabledForegroundColor: UmbraColors.accentInk,
                  ),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 0, 24, 8),
              child: TextField(
                controller: _search,
                onChanged: (v) => setState(() => _query = v),
                decoration: InputDecoration(
                  hintText: L.t('search.hint'),
                  prefixIcon: Icon(Icons.search, size: 20, color: UmbraColors.textMuted),
                  suffixIcon: _query.isEmpty
                      ? null
                      : IconButton(
                          icon: Icon(Icons.close, size: 18, color: UmbraColors.textMuted),
                          onPressed: () => setState(() {
                            _search.clear();
                            _query = '';
                          }),
                        ),
                  isDense: true,
                ),
              ),
            ),
            if (_query.trim().isNotEmpty)
              Expanded(
                child: _SearchResults(
                  query: _query,
                  onSelect: (chat) => onSelect?.call(chat),
                  onSelectGroup: (group) => onSelectGroup?.call(group),
                ),
              )
            else ...[
            if (waiting.isNotEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 0, 24, 8),
                child: _WaitingSection(waiting: waiting),
              ),
            if (chats.isEmpty && groups.isEmpty && waiting.isEmpty)
              Expanded(child: _EmptyChats())
            else
            Expanded(
              // Groups sit on top of the 1:1 conversations in one list.
              child: ListView.separated(
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
                itemCount: groups.length + chats.length,
                separatorBuilder: (_, _) => const SizedBox(height: 10),
                itemBuilder: (context, i) {
                  if (i < groups.length) {
                    return _GroupTile(
                      group: groups[i],
                      selected: groups[i].idHex == selectedGroupHex,
                      onTap: onSelectGroup,
                    );
                  }
                  final chat = chats[i - groups.length];
                  return _ChatTile(
                    chat: chat,
                    selected: chat.contactHex == selectedHex,
                    onTap: onSelect,
                  );
                },
              ),
            ),
            ],
          ],
        );
      },
    );
  }
}

/// People, groups and single messages that match what was typed.
class _SearchResults extends StatelessWidget {
  const _SearchResults({
    required this.query,
    required this.onSelect,
    required this.onSelectGroup,
  });

  final String query;
  final void Function(Chat) onSelect;
  final void Function(GroupChat) onSelectGroup;

  @override
  Widget build(BuildContext context) {
    final results = appState.search(query);
    if (results.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(L.t('search.none').replaceAll('{q}', query.trim()),
              textAlign: TextAlign.center,
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
        ),
      );
    }
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 4),
      children: [
        if (results.people.isNotEmpty) ...[
          _SearchHeading(L.t('search.people')),
          for (final c in results.people)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _ChatTile(chat: c, onTap: onSelect),
            ),
        ],
        if (results.groups.isNotEmpty) ...[
          _SearchHeading(L.t('search.groups')),
          for (final g in results.groups)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _GroupTile(group: g, onTap: onSelectGroup),
            ),
        ],
        if (results.messages.isNotEmpty) ...[
          _SearchHeading(L.t('search.messages')),
          for (final m in results.messages)
            _MessageHit(
              hit: m,
              query: query.trim(),
              onOpen: () {
                if (m.groupHex.isEmpty) {
                  final chat = appState.chats
                      .where((c) => c.contactHex == m.peerHex)
                      .firstOrNull;
                  if (chat == null) return;
                  // The conversation reads this as it opens and scrolls to the
                  // line that was clicked, rather than to the bottom.
                  appState.pendingJumpMessageId = m.messageId;
                  onSelect(chat);
                } else {
                  final group = appState.groupById(m.groupHex);
                  if (group == null) return;
                  appState.pendingJumpMessageId = m.messageId;
                  onSelectGroup(group);
                }
              },
            ),
        ],
      ],
    );
  }
}

class _SearchHeading extends StatelessWidget {
  const _SearchHeading(this.text);
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 12, 4, 8),
      child: Text(text,
          style: TextStyle(
              color: UmbraColors.accent,
              fontSize: 12,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.4)),
    );
  }
}

/// One matching message: where it was written, by whom, and the line itself
/// with the match highlighted.
class _MessageHit extends StatelessWidget {
  const _MessageHit({required this.hit, required this.query, required this.onOpen});
  final SearchHitView hit;
  final String query;
  final VoidCallback onOpen;

  String _where() {
    if (hit.groupHex.isNotEmpty) {
      final group = appState.groupById(hit.groupHex);
      return group?.name ?? L.t('search.inGroup');
    }
    final chat = appState.chats.where((c) => c.contactHex == hit.peerHex).firstOrNull;
    return chat?.name ?? L.t('chats.unknown');
  }

  @override
  Widget build(BuildContext context) {
    final at = DateTime.fromMillisecondsSinceEpoch(hit.sentAt.toInt() * 1000);
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: onOpen,
        child: Panel(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(hit.groupHex.isEmpty ? Icons.person_outline : Icons.groups,
                      size: 14, color: UmbraColors.textMuted),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      '${hit.outgoing ? L.t('groups.you') : _where()} • ${_hhmm(at)} ${at.day}. ${at.month}.',
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 11),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              _Highlighted(text: hit.body, needle: query),
            ],
          ),
        ),
      ),
    );
  }
}

/// The matched part of a line, marked so the eye lands on it.
class _Highlighted extends StatelessWidget {
  const _Highlighted({required this.text, required this.needle});
  final String text;
  final String needle;

  @override
  Widget build(BuildContext context) {
    final base = TextStyle(color: UmbraColors.textPrimary, fontSize: 13, height: 1.3);
    final start = text.toLowerCase().indexOf(needle.toLowerCase());
    if (start < 0 || needle.isEmpty) {
      return Text(text, maxLines: 3, overflow: TextOverflow.ellipsis, style: base);
    }
    final end = start + needle.length;
    return RichText(
      maxLines: 3,
      overflow: TextOverflow.ellipsis,
      text: TextSpan(style: base, children: [
        TextSpan(text: text.substring(0, start)),
        TextSpan(
          text: text.substring(start, end),
          style: base.copyWith(
            color: UmbraColors.accent,
            fontWeight: FontWeight.w700,
            backgroundColor: UmbraColors.accent.withValues(alpha: 0.12),
          ),
        ),
        TextSpan(text: text.substring(end)),
      ]),
    );
  }
}

/// First run: no contacts, no groups, nothing waiting. Say what to do instead
/// of showing an empty box.
class _EmptyChats extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.forum_outlined, size: 40, color: UmbraColors.textMuted),
            const SizedBox(height: 14),
            Text(L.t('chats.emptyTitle'),
                textAlign: TextAlign.center,
                style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
            const SizedBox(height: 6),
            Text(
              L.t('chats.emptyHelp'),
              textAlign: TextAlign.center,
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 13, height: 1.4),
            ),
            const SizedBox(height: 18),
            FilledButton.icon(
              onPressed: () => showAddContact(context),
              icon: const Icon(Icons.person_add_alt_1, size: 18),
              label: Text(L.t('chats.add')),
            ),
          ],
        ),
      ),
    );
  }
}

/// A quiet date line between messages from different days.
class _DaySeparator extends StatelessWidget {
  const _DaySeparator({required this.day});
  final DateTime day;

  String _label() {
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);
    final that = DateTime(day.year, day.month, day.day);
    final diff = today.difference(that).inDays;
    if (diff == 0) return L.t('chat.today');
    if (diff == 1) return L.t('chat.yesterday');
    return '${that.day}. ${that.month}. ${that.year}';
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 10),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        decoration: BoxDecoration(
          color: UmbraColors.surfaceHigh,
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: UmbraColors.border),
        ),
        child: Text(_label(),
            style: TextStyle(color: UmbraColors.textMuted, fontSize: 11)),
      ),
    );
  }
}

/// Messages from people we do not know yet. You can read what they wrote
/// before deciding — that is the only way to tell a friend from a stranger —
/// but nothing else happens until you accept or block them.
class _WaitingSection extends StatelessWidget {
  const _WaitingSection({required this.waiting});
  final List<Chat> waiting;

  @override
  Widget build(BuildContext context) {
    return Panel(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.mark_email_unread_outlined, size: 17, color: UmbraColors.accent),
              const SizedBox(width: 10),
              Text('${L.t('waiting.title')} (${waiting.length})',
                  style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
            ],
          ),
          const SizedBox(height: 2),
          Text(L.t('waiting.help'),
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
          for (final chat in waiting) _WaitingTile(chat: chat),
        ],
      ),
    );
  }
}

class _WaitingTile extends StatelessWidget {
  const _WaitingTile({required this.chat});
  final Chat chat;

  @override
  Widget build(BuildContext context) {
    final last = chat.messages.isEmpty ? null : chat.messages.last;
    return Padding(
      padding: const EdgeInsets.only(top: 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 14,
                backgroundColor: UmbraColors.surfaceHigh,
                child: Icon(Icons.person_outline, size: 15, color: UmbraColors.textMuted),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(chat.name,
                        style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
                    Text(chat.userCode,
                        style: TextStyle(
                            color: UmbraColors.textMuted, fontSize: 10, fontFamily: 'monospace')),
                  ],
                ),
              ),
            ],
          ),
          if (last != null)
            Padding(
              padding: const EdgeInsets.only(left: 38, top: 4),
              child: Text(
                last.body,
                maxLines: 3,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(color: UmbraColors.textPrimary, fontSize: 13, height: 1.3),
              ),
            ),
          Padding(
            padding: const EdgeInsets.only(left: 30),
            child: Row(
              children: [
                TextButton.icon(
                  onPressed: () => appState.setChatStatus(chat, 1),
                  icon: const Icon(Icons.check, size: 16),
                  label: Text(L.t('waiting.accept')),
                ),
                TextButton.icon(
                  onPressed: () => appState.setChatStatus(chat, 2),
                  icon: Icon(Icons.block, size: 16, color: UmbraColors.danger),
                  label: Text(L.t('waiting.block'),
                      style: TextStyle(color: UmbraColors.danger)),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// The address book, as its own section in the left bar: contacts kept on
/// purpose, with everything you can do to one of them in a single menu.
class ContactsScreen extends StatelessWidget {
  const ContactsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final saved = appState.savedContacts;
        final blocked = appState.blockedContacts;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ScreenHeader(
              L.t('contacts.title'),
              subtitle: L.t('contacts.subtitle'),
              trailing: FilledButton.icon(
                onPressed: () => showAddContact(context),
                icon: const Icon(Icons.person_add_alt_1, size: 18),
                label: Text(L.t('chats.add')),
              ),
            ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
                children: [
                  if (saved.isEmpty && blocked.isEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 40),
                      child: Text(L.t('contacts.empty'),
                          textAlign: TextAlign.center,
                          style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                    ),
                  for (final c in saved) _ContactRow(chat: c),
                  if (blocked.isNotEmpty) ...[
                    const SizedBox(height: 18),
                    Text(L.t('contacts.blocked'),
                        style: TextStyle(
                            color: UmbraColors.textMuted,
                            fontSize: 12,
                            fontWeight: FontWeight.w600)),
                    for (final c in blocked) _ContactRow(chat: c, blocked: true),
                  ],
                ],
              ),
            ),
          ],
        );
      },
    );
  }
}

class _ContactRow extends StatelessWidget {
  const _ContactRow({required this.chat, this.blocked = false});
  final Chat chat;
  final bool blocked;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      dense: true,
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (ctx) => Scaffold(
            body: SafeArea(
              child: ContactDetailScreen(chat: chat, onBack: () => Navigator.of(ctx).pop()),
            ),
          ),
        ),
      ),
      leading: ContactAvatar(chat: chat, radius: 16),
      title: Text(chat.name, style: const TextStyle(fontSize: 14)),
      subtitle: Text(chat.userCode,
          style: TextStyle(fontSize: 10, fontFamily: 'monospace', color: UmbraColors.textMuted)),
      trailing: PopupMenuButton<String>(
        icon: Icon(Icons.more_vert, size: 18, color: UmbraColors.textMuted),
        onSelected: (value) {
          switch (value) {
            case 'rename':
              showRenameChat(context, chat);
              break;
            case 'unsave':
              appState.setChatSaved(chat, false);
              break;
            case 'block':
              appState.setChatStatus(chat, 2);
              break;
            case 'unblock':
              appState.setChatStatus(chat, 1);
              break;
            case 'merge':
              showMergeDialog(context, chat);
              break;
            case 'delete':
              showDeleteChat(context, chat);
              break;
          }
        },
        itemBuilder: (context) => [
          if (!blocked) ...[
            PopupMenuItem(value: 'rename', child: Text(L.t('contacts.rename'))),
            // Only worth offering when there is something to merge with.
            if (appState.chats.length > 1)
              PopupMenuItem(value: 'merge', child: Text(L.t('merge.action'))),
            PopupMenuItem(value: 'unsave', child: Text(L.t('contacts.forget'))),
            PopupMenuItem(
              value: 'block',
              child: Text(L.t('waiting.block'), style: TextStyle(color: UmbraColors.danger)),
            ),
          ] else
            PopupMenuItem(value: 'unblock', child: Text(L.t('contacts.unblock'))),
          PopupMenuItem(
            value: 'delete',
            child: Text(L.t('contacts.delete'), style: TextStyle(color: UmbraColors.danger)),
          ),
        ],
      ),
    );
  }
}

/// One person, two questions: where do we share a conversation, and what have
/// they actually written to me. The switch at the top decides which one is
/// being answered.
class ContactDetailScreen extends StatefulWidget {
  const ContactDetailScreen({super.key, required this.chat, this.onBack});
  final Chat chat;
  final VoidCallback? onBack;

  @override
  State<ContactDetailScreen> createState() => _ContactDetailScreenState();
}

class _ContactDetailScreenState extends State<ContactDetailScreen> {
  /// false = conversations, true = messages.
  bool _showMessages = false;

  /// 0 = everything, 1 = direct only, 2 = groups only.
  int _filter = 0;

  @override
  Widget build(BuildContext context) {
    final chat = widget.chat;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ScreenHeader(chat.name, subtitle: chat.userCode, onBack: widget.onBack),
        Padding(
          padding: const EdgeInsets.fromLTRB(24, 0, 24, 8),
          child: SegmentedButton<bool>(
            segments: [
              ButtonSegment(value: false, label: Text(L.t('contact.where'))),
              ButtonSegment(value: true, label: Text(L.t('contact.messages'))),
            ],
            selected: {_showMessages},
            showSelectedIcon: false,
            onSelectionChanged: (s) => setState(() => _showMessages = s.first),
          ),
        ),
        if (_showMessages)
          Padding(
            padding: const EdgeInsets.fromLTRB(24, 0, 24, 4),
            child: Wrap(
              spacing: 8,
              children: [
                for (final f in [0, 1, 2])
                  ChoiceChip(
                    label: Text(
                      [L.t('contact.all'), L.t('contact.direct'), L.t('contact.fromGroups')][f],
                    ),
                    selected: _filter == f,
                    onSelected: (_) => setState(() => _filter = f),
                  ),
              ],
            ),
          ),
        Expanded(child: _showMessages ? _messages(chat) : _conversations(chat)),
      ],
    );
  }

  Widget _conversations(Chat chat) {
    final groups = appState.groupsWith(chat);
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
      children: [
        _SearchHeading(L.t('contact.directChat')),
        _ChatTile(
          chat: chat,
          onTap: (c) {
            appState.selectedChat = c;
            appState.selectedGroup = null;
            appState.railSection = 0;
            appState.notify();
            widget.onBack?.call();
          },
        ),
        _SearchHeading('${L.t('contact.sharedGroups')} (${groups.length})'),
        if (groups.isEmpty)
          Text(L.t('contact.noGroups'),
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 13))
        else
          for (final g in groups)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _GroupTile(
                group: g,
                onTap: (group) {
                  appState.selectedGroup = group;
                  appState.selectedChat = null;
                  appState.railSection = 0;
                  appState.notify();
                  widget.onBack?.call();
                },
              ),
            ),
      ],
    );
  }

  Widget _messages(Chat chat) {
    final all = appState.messagesFrom(chat);
    final hits = all.where((h) {
      if (_filter == 1) return h.groupHex.isEmpty;
      if (_filter == 2) return h.groupHex.isNotEmpty;
      return true;
    }).toList();

    if (hits.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(L.t('contact.noMessages'),
              textAlign: TextAlign.center,
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
        ),
      );
    }
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
      children: [
        for (final h in hits)
          _MessageHit(
            hit: h,
            query: '',
            onOpen: () {
              if (h.groupHex.isEmpty) {
                appState.selectedChat = chat;
                appState.selectedGroup = null;
              } else {
                appState.selectedGroup = appState.groupById(h.groupHex);
                appState.selectedChat = null;
              }
              appState.railSection = 0;
              appState.notify();
              widget.onBack?.call();
            },
          ),
      ],
    );
  }
}

/// Rename a contact (your label for them, never sent anywhere).
void showRenameChat(BuildContext context, Chat chat) {
  final controller = TextEditingController(text: chat.name);
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(L.t('contacts.rename')),
      content: TextField(
        controller: controller,
        autofocus: true,
        decoration: InputDecoration(hintText: L.t('contacts.newName')),
        onSubmitted: (v) {
          appState.renameChat(chat, v);
          Navigator.pop(ctx);
        },
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: Text(L.t('common.cancel'))),
        FilledButton(
          onPressed: () {
            appState.renameChat(chat, controller.text);
            Navigator.pop(ctx);
          },
          child: Text(L.t('common.save')),
        ),
      ],
    ),
  );
}

/// Rename a group; the new name reaches every member with the roster.
void showRenameGroup(BuildContext context, GroupChat group) {
  final controller = TextEditingController(text: group.name);
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(L.t('groups.rename')),
      content: TextField(
        controller: controller,
        autofocus: true,
        decoration: InputDecoration(hintText: L.t('groups.name')),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: Text(L.t('common.cancel'))),
        FilledButton(
          onPressed: () {
            appState.renameGroup(group, controller.text);
            Navigator.pop(ctx);
          },
          child: Text(L.t('common.save')),
        ),
      ],
    ),
  );
}

class _GroupTile extends StatelessWidget {
  const _GroupTile({required this.group, this.selected = false, this.onTap});
  final GroupChat group;
  final bool selected;
  final void Function(GroupChat group)? onTap;

  @override
  Widget build(BuildContext context) {
    final last = group.last;
    return InkWell(
      borderRadius: BorderRadius.circular(16),
      onTap: () {
        if (onTap != null) {
          onTap!(group);
        } else {
          Navigator.of(context).push(
            MaterialPageRoute(builder: (_) => GroupDetailScreen(group: group)),
          );
        }
      },
      child: _SelectablePanel(
        selected: selected,
        child: Row(
          children: [
            CircleAvatar(
              radius: 22,
              backgroundColor: UmbraColors.accent.withValues(alpha: 0.16),
              child: Icon(Icons.groups, size: 22, color: UmbraColors.accent),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(group.name,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
                      ),
                      Text('${group.members.length}',
                          style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
                      const SizedBox(width: 2),
                      Icon(Icons.person, size: 12, color: UmbraColors.textMuted),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    last == null
                        ? L.t('chats.empty')
                        : '${last.senderName ?? L.t('groups.you')}: ${last.body}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                  ),
                ],
              ),
            ),
            if (last != null)
              Text(_hhmm(last.at), style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
          ],
        ),
      ),
    );
  }
}

class _ChatTile extends StatelessWidget {
  const _ChatTile({required this.chat, this.selected = false, this.onTap});
  final Chat chat;
  final bool selected;
  final void Function(Chat chat)? onTap;

  @override
  Widget build(BuildContext context) {
    final last = chat.last;
    return InkWell(
      borderRadius: BorderRadius.circular(16),
      onTap: () {
        if (onTap != null) {
          onTap!(chat);
        } else {
          Navigator.of(context).push(
            MaterialPageRoute(builder: (_) => ChatDetailScreen(chat: chat)),
          );
        }
      },
      child: _SelectablePanel(
        selected: selected,
        child: Row(
          children: [
            ContactAvatar(chat: chat, radius: 22),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(chat.name, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
                      const SizedBox(width: 8),
                      if (chat.verified)
                        Icon(Icons.verified_user, size: 14, color: UmbraColors.accent),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    last?.body ?? L.t('chats.empty'),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                  ),
                ],
              ),
            ),
            if (last != null)
              Text(_hhmm(last.at), style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
          ],
        ),
      ),
    );
  }
}

class ChatDetailScreen extends StatefulWidget {
  const ChatDetailScreen({
    super.key,
    required this.chat,
    this.embedded = false,
    this.onBack,
  });
  final Chat chat;
  /// True when shown next to the list (no back button needed).
  final bool embedded;
  /// Narrow layout: how to get back to the list.
  final VoidCallback? onBack;

  @override
  State<ChatDetailScreen> createState() => _ChatDetailScreenState();
}

class _ChatDetailScreenState extends State<ChatDetailScreen> {
  final _input = TextEditingController();
  final _scroll = ScrollController();

  /// Put on the message we were sent to, so it can be scrolled to once it is
  /// actually built. A `ListView.builder` only builds what is near the viewport,
  /// so there is nothing to aim at until we are roughly in the right place.
  final _jumpKey = GlobalKey();
  int? _jumpTarget;

  @override
  void initState() {
    super.initState();
    _takePendingJump();
  }

  @override
  void didUpdateWidget(ChatDetailScreen old) {
    super.didUpdateWidget(old);
    // The wide layout keeps one instance and swaps the conversation into it, so
    // arriving at a different chat is an update, not a fresh state.
    if (old.chat.contactHex != widget.chat.contactHex) _takePendingJump();
  }

  void _takePendingJump() {
    final id = appState.pendingJumpMessageId;
    if (id == null) return;
    appState.pendingJumpMessageId = null;
    WidgetsBinding.instance.addPostFrameCallback((_) => _jumpTo(id));
  }

  @override
  void dispose() {
    _input.dispose();
    _scroll.dispose();
    super.dispose();
  }

  /// Scroll until the message is on screen, then mark it.
  ///
  /// Closing in rather than computing an offset: bubbles are of every height,
  /// so there is no arithmetic that lands on one. Each pass jumps to where the
  /// message would be if they were all the same size, which is close enough
  /// that the row gets built — and once it is built, Flutter can put it exactly
  /// where we want it.
  Future<void> _jumpTo(int messageId) async {
    final messages = widget.chat.messages;
    final index = messages.indexWhere((m) => m.id == messageId);
    if (index < 0 || !mounted) return;
    setState(() => _jumpTarget = messageId);

    for (var pass = 0; pass < 12; pass++) {
      await WidgetsBinding.instance.endOfFrame;
      if (!mounted) return;
      final target = _jumpKey.currentContext;
      if (target != null && target.mounted) {
        await Scrollable.ensureVisible(
          target,
          alignment: 0.35,
          duration: const Duration(milliseconds: 220),
          curve: Curves.easeOut,
        );
        break;
      }
      if (!_scroll.hasClients || messages.length < 2) break;
      final extent = _scroll.position.maxScrollExtent;
      _scroll.jumpTo((extent * index / (messages.length - 1)).clamp(0.0, extent));
    }

    if (!mounted) return;
    appState.flashMessage(messageId);
    setState(() => _jumpTarget = null);
  }

  Future<void> _attach() async {
    final result = await FilePicker.pickFiles(withData: false);
    final path = result?.files.single.path;
    if (path == null) return;
    appState.sendFile(widget.chat, path);
  }

  void _send() {
    appState.sendMessage(widget.chat, _input.text);
    _input.clear();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.animateTo(_scroll.position.maxScrollExtent,
            duration: const Duration(milliseconds: 250), curve: Curves.easeOut);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final chat = widget.chat;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: UmbraColors.surface,
        automaticallyImplyLeading: false,
        leading: widget.embedded
            ? null
            : IconButton(
                icon: const Icon(Icons.arrow_back),
                onPressed: widget.onBack ?? () => Navigator.of(context).maybePop(),
              ),
        titleSpacing: widget.embedded ? 16 : 0,
        title: Row(
          children: [
            ContactAvatar(chat: chat, radius: 16),
            const SizedBox(width: 10),
            // Just the name. The onion address is how the app reaches them, not
            // something to read while writing to them — it lives in the contact
            // detail, where an address is what you came for.
            Text(chat.name, style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
          ],
        ),
        actions: [
          ListenableBuilder(
            listenable: appState,
            builder: (context, _) {
              final live = appState.isConnectedTo(chat.contactHex);
              return Padding(
                padding: const EdgeInsets.only(right: 12),
                child: Center(
                  child: Row(
                    children: [
                      if (live)
                        Pill(L.t('chat.connected'), icon: Icons.bolt)
                      else
                        TextButton.icon(
                          onPressed: appState.torConnected
                              ? () => appState.connectTo(chat)
                              : null,
                          icon: const Icon(Icons.link, size: 16),
                          label: Text(L.t('chat.connect')),
                        ),
                      // A live session that fell back to the classical
                      // handshake: say it where the conversation is, not in a
                      // settings screen nobody opens mid-chat.
                      if (chat.postQuantum == false) ...[
                        Tooltip(
                          message: L.t('wire.legacyHelp'),
                          child: Pill(L.t('wire.legacy'), icon: Icons.warning_amber_rounded),
                        ),
                        const SizedBox(width: 8),
                      ],
                      const SizedBox(width: 8),
                      // Verified or not, the number is one click away — the
                      // check is only worth having if it is easy to reach.
                      InkWell(
                        onTap: () => showSafetyNumberDialog(context, chat),
                        borderRadius: BorderRadius.circular(999),
                        child: chat.verified
                            ? Pill(L.t('chat.verified'), icon: Icons.verified_user)
                            : Pill(L.t('chat.unverified'), icon: Icons.help_outline),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
          // Everything you can do with this contact, in one place.
          PopupMenuButton<String>(
            icon: Icon(Icons.more_vert, color: UmbraColors.textMuted),
            onSelected: (value) {
              switch (value) {
                case 'rename':
                  showRenameChat(context, chat);
                  break;
                case 'save':
                  appState.setChatSaved(chat, !chat.saved);
                  break;
                case 'block':
                  appState.setChatStatus(chat, 2);
                  if (widget.onBack != null) widget.onBack!();
                  break;
              }
            },
            itemBuilder: (context) => [
              PopupMenuItem(value: 'rename', child: Text(L.t('contacts.rename'))),
              PopupMenuItem(
                value: 'save',
                child: Text(chat.saved ? L.t('contacts.forget') : L.t('contacts.save')),
              ),
              PopupMenuItem(
                value: 'block',
                child: Text(L.t('waiting.block'), style: TextStyle(color: UmbraColors.danger)),
              ),
            ],
          ),
          const SizedBox(width: 4),
        ],
      ),
      body: Column(
        children: [
          // Live connection state for THIS contact — otherwise "Připojit" looks
          // like it does nothing while Tor is still working on the circuit.
          ListenableBuilder(
            listenable: appState,
            builder: (context, _) {
              final live = appState.isConnectedTo(chat.contactHex);
              if (live) return const SizedBox.shrink();
              // Messages written while they are away are not lost: they sit in
              // the encrypted outbox. Say so, with the count, instead of only
              // spinning.
              final waiting = chat.messages.where((m) => m.outgoing && m.pending).length;
              return Container(
                width: double.infinity,
                color: UmbraColors.surfaceHigh,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                child: Row(
                  children: [
                    if (waiting == 0)
                      const SizedBox(
                        height: 14,
                        width: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    else
                      Icon(Icons.schedule_send, size: 15, color: UmbraColors.accent),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        waiting == 0
                            ? appState.netStatus
                            : (waiting == 1 ? L.t('chat.outboxOne') : L.t('chat.outbox'))
                                .replaceAll('{n}', '$waiting')
                                .replaceAll('{name}', chat.name),
                        style: TextStyle(color: UmbraColors.textMuted, fontSize: 12),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
          Expanded(
            child: ListenableBuilder(
              listenable: appState,
              builder: (context, _) => ListView.builder(
                controller: _scroll,
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
                itemCount: chat.messages.length,
                itemBuilder: (context, i) {
                  final msg = chat.messages[i];
                  final anchor = msg.id == _jumpTarget ? _jumpKey : null;
                  // A date line where the day changes, so a long history stays
                  // readable.
                  final prev = i == 0 ? null : chat.messages[i - 1].at;
                  final newDay = prev == null ||
                      prev.day != msg.at.day ||
                      prev.month != msg.at.month ||
                      prev.year != msg.at.year;
                  if (!newDay) return _Bubble(key: anchor, msg: msg, chat: chat);
                  return Column(
                    children: [
                      _DaySeparator(day: msg.at),
                      _Bubble(key: anchor, msg: msg, chat: chat),
                    ],
                  );
                },
              ),
            ),
          ),
          _Composer(
            controller: _input,
            onSend: _send,
            onAttach: _attach,
            onGif: () => showGifPicker(context, widget.chat.contactHex),
          ),
        ],
      ),
    );
  }
}

/// A group conversation: same bubbles as a 1:1 chat, but every incoming message
/// is labelled with its sender, and the header manages the roster.
class GroupDetailScreen extends StatefulWidget {
  const GroupDetailScreen({
    super.key,
    required this.group,
    this.embedded = false,
    this.onBack,
    this.onLeft,
  });
  final GroupChat group;
  final bool embedded;
  final VoidCallback? onBack;

  /// Called after we leave, so the pane showing this group can close.
  final VoidCallback? onLeft;

  @override
  State<GroupDetailScreen> createState() => _GroupDetailScreenState();
}

class _GroupDetailScreenState extends State<GroupDetailScreen> {
  final _input = TextEditingController();
  final _scroll = ScrollController();

  @override
  void dispose() {
    _input.dispose();
    _scroll.dispose();
    super.dispose();
  }

  void _send() {
    appState.sendGroupMessage(widget.group, _input.text);
    _input.clear();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.animateTo(_scroll.position.maxScrollExtent,
            duration: const Duration(milliseconds: 250), curve: Curves.easeOut);
      }
    });
  }

  Future<void> _leave() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: UmbraColors.surfaceHigh,
        title: Text(L.t('groups.leaveTitle')),
        content: Text(L.t('groups.leaveBody'),
            style: TextStyle(color: UmbraColors.textMuted)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(L.t('common.cancel'))),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: UmbraColors.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(L.t('groups.leave')),
          ),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    appState.leaveGroup(widget.group);
    widget.onLeft?.call();
    if (!widget.embedded && mounted) Navigator.of(context).maybePop();
  }

  @override
  Widget build(BuildContext context) {
    final group = widget.group;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: UmbraColors.surface,
        automaticallyImplyLeading: false,
        leading: widget.embedded
            ? null
            : IconButton(
                icon: const Icon(Icons.arrow_back),
                onPressed: widget.onBack ?? () => Navigator.of(context).maybePop(),
              ),
        titleSpacing: widget.embedded ? 16 : 0,
        title: ListenableBuilder(
          listenable: appState,
          builder: (context, _) {
            final online = group.members.where((m) => appState.isConnectedTo(m.identityHex)).length;
            return Row(
              children: [
                CircleAvatar(
                  radius: 16,
                  backgroundColor: UmbraColors.accent.withValues(alpha: 0.16),
                  child: Icon(Icons.groups, size: 17, color: UmbraColors.accent),
                ),
                const SizedBox(width: 10),
                Flexible(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(group.name,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
                      Text(
                        L
                            .t('groups.memberLine')
                            .replaceAll('{n}', '${group.members.length}')
                            .replaceAll('{online}', '$online'),
                        style: TextStyle(fontSize: 11, color: UmbraColors.textMuted),
                      ),
                    ],
                  ),
                ),
              ],
            );
          },
        ),
        actions: [
          IconButton(
            tooltip: L.t('groups.rename'),
            icon: const Icon(Icons.drive_file_rename_outline, size: 20),
            onPressed: () => showRenameGroup(context, group),
          ),
          IconButton(
            tooltip: L.t('groups.addMember'),
            icon: const Icon(Icons.person_add_alt_1, size: 20),
            onPressed: () => showAddGroupMember(context, group),
          ),
          IconButton(
            tooltip: L.t('groups.leave'),
            icon: Icon(Icons.logout, size: 20, color: UmbraColors.danger),
            onPressed: _leave,
          ),
          const SizedBox(width: 6),
        ],
      ),
      body: Column(
        children: [
          // A group message only reaches whoever is online right now — say so
          // instead of letting it look like normal delivery.
          Container(
            width: double.infinity,
            color: UmbraColors.surfaceHigh,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Row(
              children: [
                Icon(Icons.info_outline, size: 14, color: UmbraColors.textMuted),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(L.t('groups.onlineOnly'),
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
                ),
              ],
            ),
          ),
          Expanded(
            child: ListenableBuilder(
              listenable: appState,
              builder: (context, _) => ListView.builder(
                controller: _scroll,
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
                itemCount: group.messages.length,
                itemBuilder: (context, i) => _Bubble(msg: group.messages[i]),
              ),
            ),
          ),
          // Only in groups: a mention needs somebody to mention.
          _MentionBar(controller: _input, group: widget.group),
          _Composer(controller: _input, onSend: _send),
        ],
      ),
    );
  }
}

/// Pick a name and the contacts to start a group with.
void showCreateGroup(BuildContext context) {
  showDialog<void>(context: context, builder: (_) => const _CreateGroupDialog());
}

class _CreateGroupDialog extends StatefulWidget {
  const _CreateGroupDialog();

  @override
  State<_CreateGroupDialog> createState() => _CreateGroupDialogState();
}

class _CreateGroupDialogState extends State<_CreateGroupDialog> {
  final _name = TextEditingController();
  final _picked = <String>{};

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final chats = appState.chats;
    return AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('groups.create')),
      content: SizedBox(
        width: 380,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              controller: _name,
              autofocus: true,
              onChanged: (_) => setState(() {}),
              decoration: InputDecoration(hintText: L.t('groups.name')),
            ),
            const SizedBox(height: 14),
            Text(L.t('groups.pick'),
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
            const SizedBox(height: 6),
            if (chats.isEmpty)
              Text(L.t('groups.noContacts'),
                  style: TextStyle(color: UmbraColors.textMuted, fontSize: 13))
            else
              Flexible(
                child: ListView(
                  shrinkWrap: true,
                  children: [
                    for (final c in chats)
                      CheckboxListTile(
                        value: _picked.contains(c.contactHex),
                        onChanged: (v) => setState(() {
                          if (v == true) {
                            _picked.add(c.contactHex);
                          } else {
                            _picked.remove(c.contactHex);
                          }
                        }),
                        controlAffinity: ListTileControlAffinity.leading,
                        contentPadding: EdgeInsets.zero,
                        dense: true,
                        title: Text(c.name, style: const TextStyle(fontSize: 14)),
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
          onPressed: _name.text.trim().isEmpty || _picked.isEmpty
              ? null
              : () {
                  appState.createGroup(_name.text, _picked.toList());
                  Navigator.pop(context);
                },
          child: Text(L.t('groups.createButton')),
        ),
      ],
    );
  }
}

/// Add one of our contacts to an existing group.
void showAddGroupMember(BuildContext context, GroupChat group) {
  final candidates = appState.chats
      .where((c) => !group.members.any((m) => m.identityHex == c.contactHex))
      .toList();
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('groups.addMember')),
      content: SizedBox(
        width: 360,
        child: candidates.isEmpty
            ? Text(L.t('groups.noCandidates'),
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 13))
            : Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  for (final c in candidates)
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      dense: true,
                      leading: ContactAvatar(chat: c, radius: 16),
                      title: Text(c.name, style: const TextStyle(fontSize: 14)),
                      onTap: () {
                        appState.addToGroup(group, c.contactHex);
                        Navigator.pop(ctx);
                      },
                    ),
                ],
              ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: Text(L.t('common.cancel'))),
      ],
    ),
  );
}

class _Bubble extends StatelessWidget {
  const _Bubble({super.key, required this.msg, this.chat});
  final Message msg;

  /// The conversation this belongs to. Null in places that only display
  /// messages (search results, a contact's history), where acting on one has
  /// no obvious target.
  final Chat? chat;

  @override
  Widget build(BuildContext context) {
    final out = msg.outgoing;
    final c = chat;
    if (c == null) return _body(context, out);
    // Right-click on the desktop, long press on a phone — both land here.
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onSecondaryTapDown: (d) => showMessageMenu(context, c, msg, d.globalPosition),
      onLongPressStart: (d) => showMessageMenu(context, c, msg, d.globalPosition),
      child: _body(context, out),
    );
  }

  Widget _body(BuildContext context, bool out) {
    // Marked because the user was sent here from somewhere else and needs to be
    // told which one they clicked. It fades on its own; see `flashMessage`.
    final marked = msg.id != null && msg.id == appState.highlightedMessageId;
    return Container(
      decoration: marked
          ? BoxDecoration(
              color: UmbraColors.accent.withValues(alpha: 0.10),
              borderRadius: BorderRadius.circular(18),
            )
          : null,
      child: _row(context, out),
    );
  }

  Widget _row(BuildContext context, bool out) {
    return Align(
      alignment: out ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: out ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          // In a group the bubble has to say who wrote it.
          if (!out && msg.senderName != null && msg.senderName!.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(left: 6, top: 6),
              child: Text(msg.senderName!,
                  style: TextStyle(
                      color: UmbraColors.accent, fontSize: 11, fontWeight: FontWeight.w600)),
            ),
          Container(
            margin: const EdgeInsets.only(bottom: 4, top: 6),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            constraints: const BoxConstraints(maxWidth: 460),
            decoration: BoxDecoration(
              color: out ? UmbraColors.accent.withValues(alpha: 0.16) : UmbraColors.surface,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(14),
                topRight: const Radius.circular(14),
                bottomLeft: Radius.circular(out ? 14 : 4),
                bottomRight: Radius.circular(out ? 4 : 14),
              ),
              border: Border.all(color: out ? UmbraColors.accent.withValues(alpha: 0.3) : UmbraColors.border),
            ),
            child: Column(
              crossAxisAlignment:
                  out ? CrossAxisAlignment.end : CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                if (msg.replyTo.isNotEmpty) _QuotedLine(msg: msg, chat: chat),
                msg.isFile
                    ? _FileBody(msg: msg)
                    : _TextBody(
                        msg: msg,
                        style: TextStyle(
                            color: UmbraColors.textPrimary, height: 1.35)),
              ],
            ),
          ),
          if (msg.reactions.isNotEmpty) _ReactionChips(msg: msg, chat: chat),
          Padding(
            padding: const EdgeInsets.only(bottom: 6, left: 4, right: 4),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(_hhmm(msg.at), style: TextStyle(color: UmbraColors.textMuted, fontSize: 11)),
                if (out) ...[
                  const SizedBox(width: 6),
                  // Three honest states: still in the outbox, handed to the
                  // peer's session, confirmed by their app.
                  Icon(
                    msg.pending
                        ? Icons.schedule
                        : msg.delivered
                            ? Icons.done_all
                            : Icons.done,
                    size: 12,
                    color: msg.pending
                        ? UmbraColors.textMuted
                        : msg.delivered
                            ? UmbraColors.accent
                            : UmbraColors.textMuted,
                  ),
                  const SizedBox(width: 3),
                  Text(
                    msg.pending
                        ? L.t('chat.waiting')
                        : msg.delivered
                            ? L.t('chat.delivered')
                            : L.t('chat.sent'),
                    style: TextStyle(
                        color: msg.delivered ? UmbraColors.accent : UmbraColors.textMuted,
                        fontSize: 11),
                  ),
                  const SizedBox(width: 8),
                  Icon(Icons.lock, size: 10, color: UmbraColors.textMuted.withValues(alpha: 0.8)),
                  const SizedBox(width: 3),
                  Text('${msg.wireBytes} B',
                      style: TextStyle(color: UmbraColors.textMuted, fontSize: 11)),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Names to pick from while typing `@` in a group.
///
/// Only a way to type a name without spelling it — the mention itself is text,
/// and nothing is sent to anyone because they were named. That matters here:
/// a group message already goes to every member over their own session, so a
/// mention that "notified" someone would be a promise the transport does not
/// make, and a mention of somebody *not* in the roster must not reach them at
/// all.
class _MentionBar extends StatefulWidget {
  const _MentionBar({required this.controller, required this.group});
  final TextEditingController controller;
  final GroupChat group;

  @override
  State<_MentionBar> createState() => _MentionBarState();
}

class _MentionBarState extends State<_MentionBar> {
  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onType);
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onType);
    super.dispose();
  }

  void _onType() => setState(() {});

  /// The `@word` the caret is sitting in, if any.
  String? get _partial {
    final sel = widget.controller.selection;
    if (!sel.isValid || !sel.isCollapsed) return null;
    final upto = widget.controller.text.substring(0, sel.baseOffset);
    final at = upto.lastIndexOf('@');
    if (at < 0) return null;
    if (at > 0 && !RegExp(r'\s').hasMatch(upto[at - 1])) return null;
    final word = upto.substring(at + 1);
    if (word.contains(RegExp(r'\s'))) return null;
    return word.toLowerCase();
  }

  void _insert(String name) {
    final sel = widget.controller.selection;
    final text = widget.controller.text;
    final upto = text.substring(0, sel.baseOffset);
    final at = upto.lastIndexOf('@');
    if (at < 0) return;
    final replacement = '@$name ';
    final next = text.replaceRange(at, sel.baseOffset, replacement);
    widget.controller.value = TextEditingValue(
      text: next,
      selection: TextSelection.collapsed(offset: at + replacement.length),
    );
  }

  @override
  Widget build(BuildContext context) {
    final partial = _partial;
    if (partial == null) return const SizedBox.shrink();
    final matches = widget.group.members
        .where((m) => m.displayName.isNotEmpty)
        .where((m) => m.displayName.toLowerCase().startsWith(partial))
        .take(6)
        .toList();
    if (matches.isEmpty) return const SizedBox.shrink();
    return Container(
      height: 44,
      decoration: BoxDecoration(
        color: UmbraColors.surface,
        border: Border(top: BorderSide(color: UmbraColors.border)),
      ),
      child: ListView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        children: [
          for (final m in matches)
            Padding(
              padding: const EdgeInsets.only(right: 6),
              child: ActionChip(
                label: Text(m.displayName, style: const TextStyle(fontSize: 12)),
                backgroundColor: UmbraColors.surfaceHigh,
                side: BorderSide(color: UmbraColors.border),
                onPressed: () => _insert(m.displayName.replaceAll(' ', '')),
              ),
            ),
        ],
      ),
    );
  }
}

/// A message body with `@name` picked out, so a mention reads as one.
class _TextBody extends StatelessWidget {
  const _TextBody({required this.msg, required this.style});
  final Message msg;
  final TextStyle style;

  @override
  Widget build(BuildContext context) {
    final parts = splitMentions(msg.body);
    if (parts.length == 1) return Text(msg.body, style: style);
    return RichText(
      text: TextSpan(
        style: style,
        children: [
          for (final p in parts)
            TextSpan(
              text: p.text,
              style: p.isMention
                  ? TextStyle(
                      color: UmbraColors.accent, fontWeight: FontWeight.w600)
                  : null,
            ),
        ],
      ),
    );
  }
}

/// The line a reply answers, above the reply itself. Tapping it goes there.
class _QuotedLine extends StatelessWidget {
  const _QuotedLine({required this.msg, this.chat});
  final Message msg;
  final Chat? chat;

  @override
  Widget build(BuildContext context) {
    final gone = msg.quoted.isEmpty;
    return InkWell(
      borderRadius: BorderRadius.circular(6),
      onTap: gone ? null : () => _goToQuoted(),
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.fromLTRB(8, 4, 8, 4),
        decoration: BoxDecoration(
          border: Border(
            left: BorderSide(color: UmbraColors.accent, width: 3),
          ),
          color: UmbraColors.accent.withValues(alpha: 0.06),
        ),
        child: Text(
          gone ? L.t('reply.gone') : msg.quoted,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: UmbraColors.textMuted,
            fontSize: 12,
            height: 1.3,
            fontStyle: gone ? FontStyle.italic : null,
          ),
        ),
      ),
    );
  }

  void _goToQuoted() {
    final c = chat;
    if (c == null) return;
    final target =
        c.messages.where((m) => m.msgRef == msg.replyTo).firstOrNull;
    if (target?.id == null) return;
    appState.pendingJumpMessageId = target!.id;
    appState.showMessageInChat(c.contactHex, target.id!);
  }
}

/// The emoji people put on a message. Tapping one adds yours, or takes it back.
class _ReactionChips extends StatelessWidget {
  const _ReactionChips({required this.msg, this.chat});
  final Message msg;
  final Chat? chat;

  @override
  Widget build(BuildContext context) {
    final entries = msg.reactions.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    return Padding(
      padding: const EdgeInsets.only(bottom: 2, left: 4, right: 4),
      child: Wrap(
        spacing: 4,
        children: [
          for (final e in entries)
            InkWell(
              borderRadius: BorderRadius.circular(12),
              onTap: chat == null ? null : () => appState.react(chat!, msg, e.key),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                  color: msg.myReaction == e.key
                      ? UmbraColors.accent.withValues(alpha: 0.18)
                      : UmbraColors.surface,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: msg.myReaction == e.key
                        ? UmbraColors.accent
                        : UmbraColors.border,
                  ),
                ),
                child: Text(
                  e.value > 1 ? '${e.key} ${e.value}' : e.key,
                  style: const TextStyle(fontSize: 12),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _Composer extends StatelessWidget {
  const _Composer({
    required this.controller,
    required this.onSend,
    this.onAttach,
    this.onGif,
  });
  final TextEditingController controller;
  final VoidCallback onSend;

  /// Null where attachments are not supported yet (groups).
  final VoidCallback? onAttach;

  /// Null in groups, where a GIF would have to be sent to each member
  /// separately and the cost is not obvious to the sender.
  final VoidCallback? onGif;

  @override
  Widget build(BuildContext context) {
    final answering = appState.replyingTo;
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 10, 16, 16),
      decoration: BoxDecoration(
        color: UmbraColors.surface,
        border: Border(top: BorderSide(color: UmbraColors.border)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // What is being answered, so it is obvious before pressing send —
          // and cancellable, because a reply banner nobody can dismiss is how
          // people end up answering the wrong message.
          if (answering != null)
            Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.fromLTRB(10, 6, 4, 6),
              decoration: BoxDecoration(
                color: UmbraColors.accent.withValues(alpha: 0.07),
                borderRadius: BorderRadius.circular(8),
                border: Border(
                    left: BorderSide(color: UmbraColors.accent, width: 3)),
              ),
              child: Row(
                children: [
                  Icon(Icons.reply, size: 14, color: UmbraColors.accent),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      answering.isFile
                          ? (answering.fileName ?? L.t('msg.infoFile'))
                          : answering.body,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                          color: UmbraColors.textMuted, fontSize: 12),
                    ),
                  ),
                  IconButton(
                    iconSize: 16,
                    visualDensity: VisualDensity.compact,
                    tooltip: L.t('common.cancel'),
                    icon: Icon(Icons.close, color: UmbraColors.textMuted),
                    onPressed: appState.cancelReply,
                  ),
                ],
              ),
            ),
          Row(
            children: [
              IconButton(
                tooltip: L.t('chat.attach'),
                icon: Icon(Icons.attach_file, color: UmbraColors.textMuted),
                onPressed: onAttach,
              ),
              if (onGif != null)
                IconButton(
                  tooltip: L.t('gif.tooltip'),
                  icon: Icon(Icons.gif_box_outlined, color: UmbraColors.textMuted),
                  onPressed: onGif,
                ),
              Expanded(
                child: TextField(
                  controller: controller,
                  minLines: 1,
                  maxLines: 4,
                  textInputAction: TextInputAction.send,
                  onSubmitted: (_) => onSend(),
                  decoration: InputDecoration(hintText: L.t('chat.compose')),
                ),
              ),
              const SizedBox(width: 10),
              SizedBox(
                height: 48,
                width: 48,
                child: FilledButton(
                  onPressed: onSend,
                  style: FilledButton.styleFrom(
                    padding: EdgeInsets.zero,
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12)),
                  ),
                  child: const Icon(Icons.arrow_upward_rounded, size: 22),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}


/// A file inside a chat bubble.
///
/// A photo, a video or a GIF is shown, not described: the filename above a
/// picture is noise, and every other chat app leaves it out. Anything else —
/// a document, an archive, a file that turned out not to be viewable — keeps
/// the row with its name and size, because there the name is the only thing
/// identifying it. Saving moved to the right-click menu, where the rest of the
/// per-message actions live.
class _FileBody extends StatefulWidget {
  const _FileBody({required this.msg});
  final Message msg;

  @override
  State<_FileBody> createState() => _FileBodyState();
}

class _FileBodyState extends State<_FileBody> {
  /// Null until the preview reports back; keeps the row from flashing in and
  /// out while the file is being decrypted.
  bool? _picture;

  String _size(int? bytes) {
    final b = bytes ?? 0;
    if (b >= 1024 * 1024) return '${(b / 1024 / 1024).toStringAsFixed(1)} MB';
    if (b >= 1024) return '${(b / 1024).toStringAsFixed(0)} kB';
    return '$b B';
  }

  @override
  Widget build(BuildContext context) {
    final msg = widget.msg;
    final done = (msg.progress ?? 0) >= 1;
    final media = looksLikeMedia(msg.fileName);
    // Hide the name for something that reads as media, unless the preview came
    // back saying it cannot be shown after all.
    final hideName = media && _picture != false;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (!hideName)
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(done ? Icons.insert_drive_file : Icons.downloading,
                  size: 18, color: UmbraColors.accent),
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  msg.fileName ?? msg.body,
                  style: TextStyle(color: UmbraColors.textPrimary, height: 1.3),
                ),
              ),
              const SizedBox(width: 8),
              Text(_size(msg.fileSize),
                  style: TextStyle(color: UmbraColors.textMuted, fontSize: 11)),
            ],
          ),
        if (!done) ...[
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(999),
            child: LinearProgressIndicator(
              value: msg.progress,
              minHeight: 4,
              backgroundColor: UmbraColors.surfaceHigh,
            ),
          ),
        ],
        if (done && msg.filePath != null)
          Padding(
            padding: EdgeInsets.only(top: hideName ? 0 : 8),
            child: AttachmentPreview(
              path: msg.filePath!,
              name: msg.fileName ?? 'file',
              size: msg.fileSize,
              onShown: (showing) {
                if (mounted && _picture != showing) {
                  setState(() => _picture = showing);
                }
              },
            ),
          ),
      ],
    );
  }
}


/// Contact avatar: their picture when they sent one, otherwise their initial.
class ContactAvatar extends StatelessWidget {
  const ContactAvatar({super.key, required this.chat, this.radius = 22});
  final Chat chat;
  final double radius;

  @override
  Widget build(BuildContext context) {
    final path = chat.picturePath;
    if (path != null && path.isNotEmpty && File(path).existsSync()) {
      return CircleAvatar(
        radius: radius,
        backgroundColor: UmbraColors.surfaceHigh,
        backgroundImage: FileImage(File(path)),
      );
    }
    return CircleAvatar(
      radius: radius,
      backgroundColor: UmbraColors.surfaceHigh,
      child: Text(
        chat.name.isEmpty ? '?' : chat.name.characters.first.toUpperCase(),
        style: TextStyle(
            color: UmbraColors.accent,
            fontWeight: FontWeight.w700,
            fontSize: radius * 0.62),
      ),
    );
  }
}


/// A chat row that can show a selected state (used by the split layout).
class _SelectablePanel extends StatelessWidget {
  const _SelectablePanel({required this.selected, required this.child});
  final bool selected;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: selected ? UmbraColors.surfaceHigh : UmbraColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: selected ? UmbraColors.accent.withValues(alpha: 0.55) : UmbraColors.border,
        ),
      ),
      child: child,
    );
  }
}

/// Shown on the right until a conversation is picked.
class NoChatSelected extends StatelessWidget {
  const NoChatSelected({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: UmbraColors.bg,
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.forum_outlined, size: 46, color: UmbraColors.border),
            const SizedBox(height: 14),
            Text(
              L.t('chats.pickOne'),
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
            ),
          ],
        ),
      ),
    );
  }
}
