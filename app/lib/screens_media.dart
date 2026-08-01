// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Everything that was ever sent or received as a file, in one place.
//
// The point is to answer "where is that picture" without remembering who sent
// it or when. So this is a view over the history, not a second store: every
// entry knows the message it arrived on and hands back to the conversation,
// which is where a file means something.
//
// Thumbnails follow the same rule as the bubbles do — the sealed copy is
// decrypted into memory to be shown and never written out readable. Only what
// is on screen is decrypted, because a hundred attachments decrypted at once to
// draw a grid would be a hundred copies in memory for no reason.

import 'package:flutter/material.dart';

import 'attachment_preview.dart';
import 'l10n.dart';
import 'mock.dart';
import 'screens_chats.dart' show ScreenHeader;
import 'theme.dart';

class MediaScreen extends StatefulWidget {
  const MediaScreen({super.key});

  @override
  State<MediaScreen> createState() => _MediaScreenState();
}

class _MediaScreenState extends State<MediaScreen> {
  final _search = TextEditingController();
  MediaFilter _filter = MediaFilter.all;
  List<MediaEntry>? _all;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  void _reload() {
    setState(() => _all = appState.media());
  }

  List<MediaEntry> get _shown {
    final all = _all ?? const <MediaEntry>[];
    final needle = _search.text.trim().toLowerCase();
    return all.where((e) {
      if (_filter != MediaFilter.all && e.kind != _filter) return false;
      if (needle.isEmpty) return true;
      // The name, and who it was with: "that video from Petr" is how people
      // actually look for a file.
      final who = appState.chats
              .where((c) => c.contactHex == e.peerHex)
              .firstOrNull
              ?.name
              .toLowerCase() ??
          '';
      return e.name.toLowerCase().contains(needle) || who.contains(needle);
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final shown = _shown;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ScreenHeader(
              L.t('media.title'),
              subtitle: L.t('media.subtitle'),
              trailing: IconButton(
                tooltip: L.t('media.refresh'),
                onPressed: _reload,
                icon: Icon(Icons.refresh, color: UmbraColors.textMuted),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 0, 24, 8),
              child: TextField(
                controller: _search,
                onChanged: (_) => setState(() {}),
                decoration: InputDecoration(
                  hintText: L.t('media.searchHint'),
                  prefixIcon: Icon(Icons.search, size: 20, color: UmbraColors.textMuted),
                  suffixIcon: _search.text.isEmpty
                      ? null
                      : IconButton(
                          icon: Icon(Icons.close, size: 18, color: UmbraColors.textMuted),
                          onPressed: () => setState(_search.clear),
                        ),
                ),
              ),
            ),
            SizedBox(
              height: 40,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 24),
                children: [
                  for (final f in MediaFilter.values)
                    Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: ChoiceChip(
                        label: Text(_filterLabel(f)),
                        selected: _filter == f,
                        onSelected: (_) => setState(() => _filter = f),
                        showCheckmark: false,
                        backgroundColor: UmbraColors.surface,
                        selectedColor: UmbraColors.accent.withValues(alpha: 0.2),
                        side: BorderSide(
                          color: _filter == f ? UmbraColors.accent : UmbraColors.border,
                        ),
                        labelStyle: TextStyle(
                          fontSize: 12,
                          color: _filter == f ? UmbraColors.accent : UmbraColors.textMuted,
                        ),
                      ),
                    ),
                ],
              ),
            ),
            Expanded(
              child: shown.isEmpty
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.all(32),
                        child: Text(
                          _all == null || _all!.isEmpty
                              ? L.t('media.empty')
                              : L.t('media.noMatch'),
                          textAlign: TextAlign.center,
                          style: TextStyle(color: UmbraColors.textMuted, fontSize: 13),
                        ),
                      ),
                    )
                  : GridView.builder(
                      padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
                      gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
                        maxCrossAxisExtent: 190,
                        mainAxisSpacing: 12,
                        crossAxisSpacing: 12,
                        childAspectRatio: 0.82,
                      ),
                      itemCount: shown.length,
                      itemBuilder: (context, i) => _MediaCard(entry: shown[i]),
                    ),
            ),
          ],
        );
      },
    );
  }

  String _filterLabel(MediaFilter f) => switch (f) {
        MediaFilter.all => L.t('media.all'),
        MediaFilter.photos => L.t('media.photos'),
        MediaFilter.videos => L.t('media.videos'),
        MediaFilter.gifs => L.t('media.gifs'),
        MediaFilter.files => L.t('media.files'),
      };
}

/// One attachment: a preview if it is something we can draw, the name and who
/// it was with either way.
class _MediaCard extends StatelessWidget {
  const _MediaCard({required this.entry});
  final MediaEntry entry;

  String get _who {
    final chat =
        appState.chats.where((c) => c.contactHex == entry.peerHex).firstOrNull;
    final name = chat?.name ?? L.t('chats.unknown');
    return entry.outgoing ? '${L.t('groups.you')} → $name' : name;
  }

  String get _size {
    final b = entry.size;
    if (b >= 1024 * 1024) return '${(b / 1024 / 1024).toStringAsFixed(1)} MB';
    if (b >= 1024) return '${(b / 1024).toStringAsFixed(0)} kB';
    return '$b B';
  }

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(14),
      // The conversation is where a file has its context — who sent it, what was
      // said around it. So this opens the message rather than the file.
      onTap: () => appState.showMessageInChat(entry.peerHex, entry.messageId),
      onSecondaryTapDown: (_) => _openFullScreen(context),
      onLongPress: () => _openFullScreen(context),
      child: Panel(
        padding: EdgeInsets.zero,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(
              child: ClipRRect(
                borderRadius: const BorderRadius.vertical(top: Radius.circular(13)),
                child: AttachmentPreview(
                  path: entry.path,
                  name: entry.name,
                  size: entry.size,
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(10, 8, 10, 10),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    entry.name.isEmpty ? L.t('media.unnamed') : entry.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    '$_who • $_size',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(fontSize: 11, color: UmbraColors.textMuted),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _openFullScreen(BuildContext context) =>
      openAttachmentFullScreen(context, entry.path, entry.name);
}
