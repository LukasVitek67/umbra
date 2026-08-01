// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The per-message menu: right-click on the desktop, long press on a phone.
//
// It offers what NullChat can actually do. Two things every other messenger has
// are missing on purpose rather than by oversight:
//
//   * **Reply** needs a message to be referable on the wire, and frames carry
//     no message id. Adding one is a wire change both sides must understand,
//     which is a release of its own — not a menu item.
//   * **Pin / star** would be a second place where "which message matters to
//     you" is written down. That is worth doing deliberately, with the same
//     care as the rest of the store, not bolted on here.
//
// Delete is local and says so: the copy on the other side belongs to them, and
// nothing here can reach it. Claiming otherwise would be the one lie a
// messenger like this must never tell.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'attachment_preview.dart';
import 'l10n.dart';
import 'mock.dart';
import 'theme.dart';

/// The emoji offered without opening anything further.
///
/// Six, because a row people can hit without reading is worth more than a
/// catalogue nobody scrolls. Anything else is still a message.
const List<String> kQuickReactions = ['👍', '❤️', '😂', '😮', '😢', '🔥'];

/// Show the menu for `msg` at the pointer.
Future<void> showMessageMenu(
  BuildContext context,
  Chat chat,
  Message msg,
  Offset position,
) async {
  final overlay = Overlay.of(context).context.findRenderObject() as RenderBox?;
  if (overlay == null) return;
  final hasFile = msg.filePath != null;

  // A row of emoji above the menu, because reacting is the one thing here
  // people do without thinking about it — putting it behind a submenu would
  // make it slower than typing the emoji as a message.
  if (msg.msgRef.isNotEmpty) {
    final picked = await showMenu<String>(
      context: context,
      color: UmbraColors.surfaceHigh,
      position: RelativeRect.fromRect(
        position & const Size(1, 1),
        Offset.zero & overlay.size,
      ),
      items: [
        PopupMenuItem<String>(
          enabled: false,
          height: 44,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              for (final e in kQuickReactions)
                InkWell(
                  borderRadius: BorderRadius.circular(16),
                  onTap: () => Navigator.pop(context, 'react:$e'),
                  child: Container(
                    padding: const EdgeInsets.all(6),
                    decoration: msg.myReaction == e
                        ? BoxDecoration(
                            color: UmbraColors.accent.withValues(alpha: 0.18),
                            borderRadius: BorderRadius.circular(16),
                          )
                        : null,
                    child: Text(e, style: const TextStyle(fontSize: 20)),
                  ),
                ),
              const SizedBox(width: 4),
              InkWell(
                borderRadius: BorderRadius.circular(16),
                onTap: () => Navigator.pop(context, 'menu'),
                child: Padding(
                  padding: const EdgeInsets.all(6),
                  child: Icon(Icons.more_horiz, color: UmbraColors.textMuted),
                ),
              ),
            ],
          ),
        ),
      ],
    );
    if (picked == null || !context.mounted) return;
    if (picked.startsWith('react:')) {
      appState.react(chat, msg, picked.substring(6));
      return;
    }
  }

  final choice = await showMenu<String>(
    context: context,
    color: UmbraColors.surfaceHigh,
    position: RelativeRect.fromRect(
      position & const Size(1, 1),
      Offset.zero & overlay.size,
    ),
    items: [
      if (msg.msgRef.isNotEmpty) _item('reply', Icons.reply, L.t('msg.reply')),
      _item('info', Icons.info_outline, L.t('msg.info')),
      if (!hasFile) _item('copy', Icons.copy_all_outlined, L.t('msg.copy')),
      if (hasFile) _item('open', Icons.open_in_full, L.t('msg.open')),
      if (hasFile) _item('save', Icons.download_outlined, L.t('chat.saveFile')),
      _item('forward', Icons.shortcut, L.t('msg.forward')),
      const PopupMenuDivider(),
      _item('delete', Icons.delete_outline, L.t('msg.delete'), danger: true),
    ],
  );
  if (choice == null || !context.mounted) return;

  switch (choice) {
    case 'reply':
      appState.startReply(msg);
    case 'info':
      await _showInfo(context, chat, msg);
    case 'copy':
      await Clipboard.setData(ClipboardData(text: msg.body));
      appState.showInAppNotice(chat.name, L.t('msg.copied'));
    case 'open':
      await openAttachmentFullScreen(context, msg.filePath!, msg.fileName ?? '');
    case 'save':
      await appState.saveAttachment(msg.filePath!, msg.fileName ?? 'file');
    case 'forward':
      await _forward(context, chat, msg);
    case 'delete':
      await _confirmDelete(context, chat, msg);
  }
}

PopupMenuItem<String> _item(
  String value,
  IconData icon,
  String label, {
  bool danger = false,
}) {
  final colour = danger ? UmbraColors.danger : UmbraColors.textPrimary;
  return PopupMenuItem<String>(
    value: value,
    height: 40,
    child: Row(
      children: [
        Icon(icon, size: 18, color: danger ? UmbraColors.danger : UmbraColors.textMuted),
        const SizedBox(width: 12),
        Text(label, style: TextStyle(color: colour)),
      ],
    ),
  );
}

String _size(int? bytes) {
  final b = bytes ?? 0;
  if (b >= 1024 * 1024) return '${(b / 1024 / 1024).toStringAsFixed(1)} MB';
  if (b >= 1024) return '${(b / 1024).toStringAsFixed(0)} kB';
  return '$b B';
}

String _stamp(DateTime t) {
  String two(int n) => n.toString().padLeft(2, '0');
  return '${two(t.day)}.${two(t.month)}.${t.year} ${two(t.hour)}:${two(t.minute)}';
}

Future<void> _showInfo(BuildContext context, Chat chat, Message msg) {
  final rows = <(String, String)>[
    (L.t('msg.infoWho'), msg.outgoing ? L.t('msg.infoMe') : chat.name),
    (L.t('msg.infoWhen'), _stamp(msg.at)),
    if (msg.outgoing)
      (
        L.t('msg.infoState'),
        msg.delivered
            ? L.t('chat.delivered')
            : msg.pending
                ? L.t('chat.pending')
                : L.t('chat.sent')
      ),
    if (msg.fileName != null) (L.t('msg.infoFile'), msg.fileName!),
    if (msg.fileSize != null) (L.t('msg.infoSize'), _size(msg.fileSize)),
  ];

  return showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('msg.info')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          for (final (label, value) in rows)
            Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SizedBox(
                    width: 110,
                    child: Text(label,
                        style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
                  ),
                  Expanded(child: SelectableText(value, style: const TextStyle(fontSize: 13))),
                ],
              ),
            ),
          const SizedBox(height: 4),
          Text(L.t('msg.infoLocal'),
              style: TextStyle(color: UmbraColors.textMuted, fontSize: 11, height: 1.4)),
        ],
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: Text(L.t('common.close'))),
      ],
    ),
  );
}

/// Send the same thing to somebody else.
///
/// A file is forwarded from our own sealed copy, so the service it originally
/// came from is not asked again and learns nothing about it being passed on.
Future<void> _forward(BuildContext context, Chat from, Message msg) async {
  final targets = appState.openChats.where((c) => c.contactHex != from.contactHex).toList();
  if (targets.isEmpty) {
    appState.showInAppNotice(from.name, L.t('msg.forwardNobody'));
    return;
  }
  final target = await showDialog<Chat>(
    context: context,
    builder: (ctx) => SimpleDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('msg.forwardTo')),
      children: [
        for (final c in targets)
          SimpleDialogOption(
            onPressed: () => Navigator.pop(ctx, c),
            child: Row(
              children: [
                CircleAvatar(
                  radius: 14,
                  backgroundColor: UmbraColors.surface,
                  child: Text(c.name.isEmpty ? '?' : c.name.characters.first.toUpperCase(),
                      style: TextStyle(fontSize: 12, color: UmbraColors.accent)),
                ),
                const SizedBox(width: 10),
                Expanded(child: Text(c.name)),
              ],
            ),
          ),
      ],
    ),
  );
  if (target == null) return;
  appState.forwardMessage(target, msg);
}

Future<void> _confirmDelete(BuildContext context, Chat chat, Message msg) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('msg.delete')),
      content: Text(L.t('msg.deleteBody'),
          style: TextStyle(color: UmbraColors.textMuted, height: 1.4)),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(L.t('common.cancel'))),
        FilledButton(
          style: FilledButton.styleFrom(backgroundColor: UmbraColors.danger),
          onPressed: () => Navigator.pop(ctx, true),
          child: Text(L.t('msg.delete')),
        ),
      ],
    ),
  );
  if (ok == true) appState.deleteMessage(chat, msg);
}
