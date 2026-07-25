// SPDX-License-Identifier: AGPL-3.0-or-later
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'l10n.dart';
import 'mock.dart';
import 'theme.dart';

String _hhmm(DateTime t) =>
    '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';

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

class ChatsScreen extends StatelessWidget {
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
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final chats = appState.chats;
        final groups = appState.groups;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ScreenHeader(
              L.t('chats.title'),
              subtitle: L.t('chats.subtitle'),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    tooltip: L.t('groups.create'),
                    onPressed: () => showCreateGroup(context),
                    icon: const Icon(Icons.group_add_outlined),
                    color: UmbraColors.textMuted,
                  ),
                  const SizedBox(width: 4),
                  FilledButton.icon(
                    onPressed: () => showAddContact(context),
                    icon: const Icon(Icons.person_add_alt_1, size: 18),
                    label: Text(L.t('chats.add')),
                  ),
                ],
              ),
            ),
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
        );
      },
    );
  }
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

  @override
  void dispose() {
    _input.dispose();
    _scroll.dispose();
    super.dispose();
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
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(chat.name, style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
                Text(chat.onion, style: TextStyle(fontSize: 11, color: UmbraColors.textMuted)),
              ],
            ),
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
                      const SizedBox(width: 8),
                      if (chat.verified) Pill(L.t('chat.verified'), icon: Icons.verified_user),
                    ],
                  ),
                ),
              );
            },
          ),
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
              return Container(
                width: double.infinity,
                color: UmbraColors.surfaceHigh,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                child: Row(
                  children: [
                    const SizedBox(
                      height: 14,
                      width: 14,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        appState.netStatus,
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
                itemBuilder: (context, i) => _Bubble(msg: chat.messages[i]),
              ),
            ),
          ),
          _Composer(controller: _input, onSend: _send, onAttach: _attach),
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
  const _Bubble({required this.msg});
  final Message msg;

  @override
  Widget build(BuildContext context) {
    final out = msg.outgoing;
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
            child: msg.isFile
                ? _FileBody(msg: msg)
                : Text(msg.body,
                    style: TextStyle(color: UmbraColors.textPrimary, height: 1.35)),
          ),
          Padding(
            padding: const EdgeInsets.only(bottom: 6, left: 4, right: 4),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(_hhmm(msg.at), style: TextStyle(color: UmbraColors.textMuted, fontSize: 11)),
                if (out) ...[
                  const SizedBox(width: 6),
                  Icon(
                    msg.pending ? Icons.schedule : Icons.done,
                    size: 11,
                    color: msg.pending ? UmbraColors.danger : UmbraColors.accent,
                  ),
                  const SizedBox(width: 3),
                  Text(
                    msg.pending ? L.t('chat.pending') : L.t('chat.delivered'),
                    style: TextStyle(
                        color: msg.pending ? UmbraColors.danger : UmbraColors.textMuted,
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

class _Composer extends StatelessWidget {
  const _Composer({required this.controller, required this.onSend, this.onAttach});
  final TextEditingController controller;
  final VoidCallback onSend;

  /// Null where attachments are not supported yet (groups).
  final VoidCallback? onAttach;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 10, 16, 16),
      decoration: BoxDecoration(
        color: UmbraColors.surface,
        border: Border(top: BorderSide(color: UmbraColors.border)),
      ),
      child: Row(
        children: [
          IconButton(
            tooltip: L.t('chat.attach'),
            icon: Icon(Icons.attach_file, color: UmbraColors.textMuted),
            onPressed: onAttach,
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
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
              ),
              child: const Icon(Icons.arrow_upward_rounded, size: 22),
            ),
          ),
        ],
      ),
    );
  }
}


/// A file inside a chat bubble: name, size, transfer progress and — once it has
/// arrived — a way to open the folder it was saved to.
class _FileBody extends StatelessWidget {
  const _FileBody({required this.msg});
  final Message msg;

  String _size(int? bytes) {
    final b = bytes ?? 0;
    if (b >= 1024 * 1024) return '${(b / 1024 / 1024).toStringAsFixed(1)} MB';
    if (b >= 1024) return '${(b / 1024).toStringAsFixed(0)} kB';
    return '$b B';
  }

  @override
  Widget build(BuildContext context) {
    final done = (msg.progress ?? 0) >= 1;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
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
        if (done && msg.filePath != null) ...[
          const SizedBox(height: 6),
          TextButton.icon(
            onPressed: () => Process.run('explorer.exe', ['/select,', msg.filePath!]),
            icon: const Icon(Icons.folder_open, size: 15),
            label: Text(L.t('chat.showFile')),
            style: TextButton.styleFrom(
              padding: EdgeInsets.zero,
              minimumSize: const Size(0, 28),
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            ),
          ),
        ],
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
