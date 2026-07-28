// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The GIF picker.
//
// Two things about this screen are deliberate and worth knowing before
// changing it:
//
// 1. It is **off until the person turns it on**, and the first thing they see
//    is what turning it on means: searches reach Google's Tenor service (over
//    Tor, on their own circuit). Everything else in NullChat talks to nobody,
//    so quietly starting to talk to somebody would be a change made behind the
//    user's back.
//
// 2. Previews are fetched by *us* through Tor, never by an <Image.network>.
//    Handing a URL to Flutter's image loader would make the request outside
//    Tor — the exact leak this feature is designed around.

import 'dart:typed_data';

import 'package:flutter/material.dart';

import 'l10n.dart';
import 'mock.dart';
import 'src/rust/api/nullchat.dart' show GifView;
import 'theme.dart';

/// Pick a GIF and send it to [contactHex]. Returns once something was sent.
Future<void> showGifPicker(BuildContext context, String contactHex) async {
  if (!appState.gifsEnabled) {
    final agreed = await _askFirst(context);
    if (agreed != true) return;
    await appState.setGifsEnabled(true);
  }
  if (!context.mounted) return;
  await showModalBottomSheet<void>(
    context: context,
    backgroundColor: UmbraColors.surfaceHigh,
    isScrollControlled: true,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
    ),
    builder: (ctx) => _GifSheet(contactHex: contactHex),
  );
}

/// The one-time explanation. Written so somebody can decline knowingly.
Future<bool?> _askFirst(BuildContext context) {
  return showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: UmbraColors.surfaceHigh,
      title: Text(L.t('gif.enableTitle')),
      content: SizedBox(
        width: 460,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(L.t('gif.enableBody'),
                style: TextStyle(
                    color: UmbraColors.textMuted, fontSize: 13, height: 1.5)),
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: UmbraColors.surface,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: UmbraColors.border),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.lock_outline, size: 16, color: UmbraColors.accent),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(L.t('gif.enableProtected'),
                        style: TextStyle(
                            color: UmbraColors.textMuted,
                            fontSize: 12,
                            height: 1.45)),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(false),
          child: Text(L.t('gif.enableNo')),
        ),
        FilledButton(
          onPressed: () => Navigator.of(ctx).pop(true),
          child: Text(L.t('gif.enableYes')),
        ),
      ],
    ),
  );
}

class _GifSheet extends StatefulWidget {
  const _GifSheet({required this.contactHex});
  final String contactHex;

  @override
  State<_GifSheet> createState() => _GifSheetState();
}

class _GifSheetState extends State<_GifSheet> {
  final _query = TextEditingController();
  List<GifView> _results = const [];
  bool _loading = true;
  String? _error;
  int _seq = 0;

  @override
  void initState() {
    super.initState();
    _search('');
  }

  @override
  void dispose() {
    _query.dispose();
    super.dispose();
  }

  Future<void> _search(String q) async {
    final seq = ++_seq;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final found = await appState.gifSearch(q);
      // A slower earlier search must not overwrite a newer one's results.
      if (!mounted || seq != _seq) return;
      setState(() {
        _results = found;
        _loading = false;
      });
    } catch (e) {
      if (!mounted || seq != _seq) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
      child: SizedBox(
        height: MediaQuery.of(context).size.height * 0.7,
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 8),
              child: TextField(
                controller: _query,
                autofocus: true,
                onSubmitted: _search,
                decoration: InputDecoration(
                  hintText: L.t('gif.search'),
                  prefixIcon: const Icon(Icons.search, size: 20),
                  suffixIcon: IconButton(
                    icon: const Icon(Icons.arrow_forward, size: 20),
                    onPressed: () => _search(_query.text),
                  ),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Row(
                children: [
                  Icon(Icons.shield_outlined, size: 13, color: UmbraColors.textMuted),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(L.t('gif.viaTor'),
                        style: TextStyle(color: UmbraColors.textMuted, fontSize: 11)),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            Expanded(child: _body()),
          ],
        ),
      ),
    );
  }

  Widget _body() {
    if (_loading) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 12),
            Text(L.t('gif.loading'),
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 12)),
          ],
        ),
      );
    }
    if (_error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(_error!,
              textAlign: TextAlign.center,
              style: TextStyle(color: UmbraColors.danger, fontSize: 12)),
        ),
      );
    }
    if (_results.isEmpty) {
      return Center(
        child: Text(L.t('gif.none'),
            style: TextStyle(color: UmbraColors.textMuted, fontSize: 13)),
      );
    }
    return GridView.builder(
      padding: const EdgeInsets.all(12),
      gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
        maxCrossAxisExtent: 180,
        mainAxisSpacing: 8,
        crossAxisSpacing: 8,
      ),
      itemCount: _results.length,
      itemBuilder: (context, i) => _GifTile(
        gif: _results[i],
        onTap: () {
          appState.sendGif(widget.contactHex, _results[i]);
          Navigator.of(context).pop();
        },
      ),
    );
  }
}

/// One result. The preview is fetched through Tor by the Rust side — never by
/// Flutter's network image loader, which would go out over the clearnet.
class _GifTile extends StatefulWidget {
  const _GifTile({required this.gif, required this.onTap});
  final GifView gif;
  final VoidCallback onTap;

  @override
  State<_GifTile> createState() => _GifTileState();
}

class _GifTileState extends State<_GifTile> {
  Uint8List? _bytes;
  bool _failed = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final data = await appState.gifPreview(widget.gif.previewUrl);
      if (mounted) setState(() => _bytes = data);
    } catch (_) {
      if (mounted) setState(() => _failed = true);
    }
  }

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: widget.onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        decoration: BoxDecoration(
          color: UmbraColors.surface,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: UmbraColors.border),
        ),
        clipBehavior: Clip.antiAlias,
        child: _bytes != null
            ? Image.memory(_bytes!, fit: BoxFit.cover)
            : Center(
                child: _failed
                    ? Icon(Icons.broken_image_outlined,
                        size: 18, color: UmbraColors.textMuted)
                    : const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
              ),
      ),
    );
  }
}
