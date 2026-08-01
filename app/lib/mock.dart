// SPDX-License-Identifier: AGPL-3.0-or-later
//
// App state backed by the REAL NullChat core over flutter_rust_bridge. Identity,
// user code, invites, contacts and message history are genuine and persisted
// encrypted at rest. Live peer-to-peer send/receive over the transport is the
// remaining step; until then, `sendMessage` stores the message locally.

import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';

import 'app_dir.dart';
import 'l10n.dart';
import 'notifications.dart';
import 'single_instance.dart';
import 'src/rust/api/nullchat.dart';

const List<int> kPaddingBuckets = [256, 1024, 4096, 16384, 65536];

/// Mirror of the real padding rule: bytes a body occupies on the wire.
int wireBytesFor(int bodyLen) {
  final needed = bodyLen + 4;
  for (final b in kPaddingBuckets) {
    if (needed <= b) return b;
  }
  return ((needed + 65535) ~/ 65536) * 65536;
}

class Device {
  Device({
    required this.name,
    required this.platform,
    required this.fingerprint,
    required this.lastSeen,
    this.current = false,
    this.revoked = false,
  });
  final String name;
  final String platform;
  final String fingerprint;
  final String lastSeen;
  final bool current;
  bool revoked;
}

class Message {
  Message(
    this.body, {
    required this.outgoing,
    required this.at,
    this.pending = false,
    this.filePath,
    this.fileName,
    this.fileSize,
    this.senderName,
  });
  final String body;
  final bool outgoing;
  final DateTime at;

  /// Who wrote it, in a group. Null in 1:1 chats, where the header says it.
  final String? senderName;

  /// Row id in the store, when this message came from there. Null for one that
  /// only exists in this session, which cannot be deleted from the database
  /// because it is not in it yet.
  int? id;

  /// Outgoing message that has not reached the peer yet (no session). It waits
  /// in the encrypted outbox and goes out on its own once they are back.
  bool pending;
  /// The peer's app confirmed it arrived.
  bool delivered = false;

  /// Set for file messages: local path once complete, plus name and size.
  String? filePath;
  final String? fileName;
  final int? fileSize;
  /// 0..1 while a file is moving; null for plain messages.
  double? progress;

  bool get isFile => fileName != null;
  int get wireBytes => wireBytesFor(body.length);
}

class Chat {
  Chat({
    required this.contactHex,
    required this.name,
    required this.onion,
    required this.userCode,
    this.verified = false,
    List<Message>? messages,
  }) : messages = messages ?? [];
  final String contactHex;
  String name;

  /// Learned from the peer once they tell us where they live, so it changes
  /// while the app runs.
  String onion;
  final String userCode;

  /// 0 = waiting for a decision (they wrote first), 1 = accepted, 2 = blocked.
  int status = 1;

  /// Kept in the address book, so they can be picked from the contacts list.
  bool saved = false;

  bool get isWaiting => status == 0;
  bool get isBlocked => status == 2;
  /// Local path to the contact's picture, if they sent one.
  String? picturePath;
  bool verified;

  /// True once a live session with them used the hybrid handshake. Null until
  /// we have connected at all — "unknown" and "old version" are not the same
  /// thing and must not look the same.
  bool? postQuantum;
  final List<Message> messages;
  Message? get last => messages.isEmpty ? null : messages.last;
}

/// What sort of thing an attachment is, for the media overview's filter.
enum MediaFilter { all, photos, videos, gifs, files }

/// One attachment in the media overview, with the conversation it belongs to.
class MediaEntry {
  MediaEntry({
    required this.messageId,
    required this.peerHex,
    required this.outgoing,
    required this.at,
    required this.path,
    required this.name,
    required this.size,
  });

  final int messageId;
  final String peerHex;
  final bool outgoing;
  final DateTime at;
  final String path;
  final String name;
  final int size;

  /// Which filter this falls under. Decided by the name's extension, the same
  /// way the bubble in the conversation decides whether to show a preview.
  MediaFilter get kind {
    final n = name.toLowerCase();
    if (n.endsWith('.gif')) return MediaFilter.gifs;
    for (final e in const ['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.heic']) {
      if (n.endsWith(e)) return MediaFilter.photos;
    }
    for (final e in const ['.mp4', '.mov', '.webm', '.mkv', '.avi', '.m4v']) {
      if (n.endsWith(e)) return MediaFilter.videos;
    }
    return MediaFilter.files;
  }
}

/// One member of a group, as the roster knows them.
class GroupMemberInfo {
  GroupMemberInfo({required this.identityHex, required this.displayName, required this.onion});
  final String identityHex;
  final String displayName;
  final String onion;
}

/// A group conversation. Messages go out over each member's own 1:1 session,
/// so a member who is offline when we write simply does not get that message.
class GroupChat {
  GroupChat({
    required this.idHex,
    required this.name,
    required this.members,
    List<Message>? messages,
  }) : messages = messages ?? [];
  final String idHex;
  String name;
  List<GroupMemberInfo> members;
  final List<Message> messages;
  Message? get last => messages.isEmpty ? null : messages.last;
}

/// What a search turned up, kept apart so the UI can label each kind.
class SearchResults {
  const SearchResults(this.people, this.groups, this.messages);
  final List<Chat> people;
  final List<GroupChat> groups;
  final List<SearchHitView> messages;

  bool get isEmpty => people.isEmpty && groups.isEmpty && messages.isEmpty;
  int get total => people.length + groups.length + messages.length;
}

int _nowSecs() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

/// Global app state, backed by the real core.
class AppState extends ChangeNotifier {
  UmbraApp? _app;

  bool hasIdentity = false;
  /// True while the user is creating an additional account.
  bool creatingAccount = false;
  String username = '';
  String userCode = '';
  String identityFingerprint = '';
  int paddingFloorIndex = 0;
  String? lastError;

  // --- network state (Tor onion transport) ---
  /// Our own onion address; empty until the service is up.
  String onion = '';
  /// Human-readable status of the network layer.
  String netStatus = '';
  /// Identities (hex) of peers we currently have a live session with.
  final Set<String> connectedPeers = {};
  String? get connectedPeerHex => connectedPeers.isEmpty ? null : connectedPeers.first;

  bool isConnectedTo(String contactHex) => connectedPeers.contains(contactHex);

  bool get torConnected => onion.isNotEmpty;
  bool get isConnecting => hasIdentity && onion.isEmpty;

  // --- updates (checked through Tor, signature-verified in Rust) ---
  /// The version this build reports.
  String get version => appVersion();
  /// Messages waiting in the encrypted outbox for their peer to come online.
  int pendingMessages = 0;

  /// Human-readable state of the update check.
  String updateStatus = '';
  /// A newer version is on GitHub and waiting for the user to say yes.
  String? updateAvailableVersion;
  /// What changed in it, as published with the release.
  String updateNotes = '';
  /// True while it is being fetched.
  bool updateDownloading = false;
  /// 0..1 while downloading, null when the size is unknown.
  double? updateProgress;

  /// The same as a whole percentage, for the number next to the bar.
  int? get updatePercent =>
      updateProgress == null ? null : (updateProgress! * 100).clamp(0, 100).round();
  /// Why the last attempt failed, if it did.
  String? updateError;
  /// A newer version is already installed next to the app; a restart uses it.
  String? updateReadyVersion;

  /// Fetch, verify and install the version the user was offered.
  void installUpdateNow() {
    try {
      updateError = null;
      installUpdate();
      updateDownloading = true;
      updateProgress = null;
      updateStatus = L.t('update.starting');
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Dismiss the offer until the next version shows up.
  void postponeUpdate() {
    updateAvailableVersion = null;
    notifyListeners();
  }

  final List<Chat> chats = [];
  final List<GroupChat> groups = [];
  final List<Device> devices = [];

  // --- what the user is looking at ---
  //
  // Kept here, not in the shell's State: switching a colour theme rebuilds the
  // whole widget tree (that is what makes every screen take the new palette),
  // and a section or an open conversation stored in a State would be thrown
  // away with it — you would land back in Chats after picking a colour.
  /// Which rail section is open: 0 chats, 1 contacts, 2 media, 3 settings.
  int railSection = 0;
  /// The open 1:1 conversation, if any.
  Chat? selectedChat;
  /// The open group conversation, if any.
  GroupChat? selectedGroup;

  /// A message the conversation should scroll to and mark as soon as it opens.
  ///
  /// Set by whatever sent the user there — a search hit, an entry in Media —
  /// and cleared by the conversation once it has landed on it, so going back
  /// and forth does not keep re-scrolling to the same place.
  int? pendingJumpMessageId;

  /// The message drawn with a highlight right now, if any.
  int? highlightedMessageId;

  /// Open the conversation this message is in and land on the message.
  void showMessageInChat(String peerHex, int messageId) {
    final chat = chats.where((c) => c.contactHex == peerHex).firstOrNull;
    if (chat == null) return;
    pendingJumpMessageId = messageId;
    selectedGroup = null;
    selectedChat = chat;
    railSection = 0;
    notifyListeners();
  }

  /// Mark a message as the one the user was sent to, then let it fade.
  ///
  /// A highlight that stayed would become part of how the conversation looks;
  /// the point is only to answer "which one did I click".
  void flashMessage(int messageId) {
    highlightedMessageId = messageId;
    notifyListeners();
    Future.delayed(const Duration(seconds: 3), () {
      if (highlightedMessageId != messageId) return;
      highlightedMessageId = null;
      notifyListeners();
    });
  }

  /// Every attachment in the history, newest first.
  ///
  /// Read on demand rather than kept in sync: the overview is a place you visit,
  /// not something on screen while messages arrive.
  List<MediaEntry> media({int limit = 500}) {
    final app = _app;
    if (app == null) return const [];
    try {
      return app
          .media(limit: limit)
          .map((m) => MediaEntry(
                messageId: m.messageId,
                peerHex: m.peerHex,
                outgoing: m.outgoing,
                at: DateTime.fromMillisecondsSinceEpoch(m.sentAt.toInt() * 1000),
                path: m.filePath,
                name: m.fileName,
                size: m.fileSize.toInt(),
              ))
          .toList();
    } catch (e) {
      lastError = _clean(e);
      return const [];
    }
  }

  Future<String> _dir() async => AppDir.path();

  /// Accounts stored on this computer.
  Future<List<AccountView>> accounts() async =>
      UmbraApp.listAccounts(root: await _dir());

  /// Create an additional account (its own identity, keys and history).
  Future<bool> createAccount(
    String username,
    String passphrase, {
    bool autologin = false,
  }) async {
    try {
      final app = UmbraApp.createAccount(
        root: await _dir(),
        name: username,
        passphrase: passphrase,
        autologin: autologin,
      );
      creatingAccount = false;
      _adopt(app);
      return true;
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
      return false;
    }
  }

  /// Sign in to an account with its passphrase.
  Future<bool> signIn(String id, String passphrase, {bool remember = false}) async {
    try {
      final app = UmbraApp.openAccount(
        root: await _dir(),
        id: id,
        passphrase: passphrase,
        remember: remember,
      );
      _adopt(app);
      return true;
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
      return false;
    }
  }

  /// Sign in to an account whose passphrase this computer remembers.
  Future<bool> signInAuto(String id) async {
    try {
      final app = UmbraApp.openAccountAuto(root: await _dir(), id: id);
      _adopt(app);
      return true;
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
      return false;
    }
  }

  /// Delete an account and all of its local data.
  Future<void> forgetAccount(String id) async {
    try {
      UmbraApp.forgetAccount(root: await _dir(), id: id);
    } catch (e) {
      lastError = _clean(e);
    }
    notifyListeners();
  }

  /// Show the "create another account" form.
  void startNewAccountFlow() {
    creatingAccount = true;
    notifyListeners();
  }

  void cancelNewAccountFlow() {
    creatingAccount = false;
    notifyListeners();
  }

  /// Whether this account signs in automatically on this computer.
  bool get autologinEnabled => _app?.autologinEnabled() ?? false;

  /// Turn auto sign-in on (needs the passphrase) or off.
  bool setAutologin(String passphrase, bool enabled) {
    try {
      _app?.setAutologin(passphrase: passphrase, enabled: enabled);
      notifyListeners();
      return true;
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
      return false;
    }
  }

  /// Sign out and come back at the account picker.
  ///
  /// Clearing our own fields is the smaller half of this. The session lives in
  /// the Rust side — the open database, the identity key, the live Signal
  /// sessions — and a key that has been in memory leaves copies nothing owns:
  /// in the allocator's free list, in a saved stack, in the page file. No amount
  /// of setting variables to null reaches those. Leaving the process does, so
  /// that is what happens here: hand the session back, start a replacement, and
  /// quit. A lock that leaves the keys in RAM is decoration, and this app is not
  /// the place for decoration.
  ///
  /// [newAccount] carries "and then let me make another one" across the restart,
  /// since the process that was asked is not the process that answers.
  Future<void> signOut({bool newAccount = false}) async {
    try {
      UmbraApp.endSession();
    } catch (_) {
      // Nothing to hand back (never signed in, or already gone).
    }
    _clearSessionState();

    if (!_canRestart) {
      // Android has no second process to hand over to, and exiting there is
      // indistinguishable from a crash. Letting go above is what we get.
      if (newAccount) creatingAccount = true;
      notifyListeners();
      return;
    }

    try {
      // Let go of the single-instance claim first: the replacement checks for
      // it on startup and must not find us still holding it.
      await SingleInstance.release();
      await Process.start(
        Platform.resolvedExecutable,
        [kRestartFlag, if (newAccount) kNewAccountFlag],
        mode: ProcessStartMode.detached,
      );
    } catch (e) {
      // The replacement did not start. Quitting now would look like a crash and
      // leave the user with nothing, so stay up — the session is gone either
      // way, which was the point.
      lastError = _clean(e);
      if (newAccount) creatingAccount = true;
      notifyListeners();
      return;
    }
    exit(0);
  }

  /// Whether this platform can hand over to a fresh copy of itself.
  static bool get _canRestart =>
      Platform.isWindows || Platform.isLinux || Platform.isMacOS;

  /// Forget everything the signed-in account put on screen.
  void _clearSessionState() {
    _app = null;
    hasIdentity = false;
    username = '';
    userCode = '';
    identityFingerprint = '';
    onion = '';
    connectedPeers.clear();
    chats.clear();
    groups.clear();
    devices.clear();
    _clearAttachmentCache();
    netStatus = '';
  }

  void _adopt(UmbraApp app) {
    _app = app;
    username = app.username();
    userCode = app.userCode();
    identityFingerprint = _group(app.identityHex());
    hasIdentity = true;
    // Before anything can arrive: an account with duress passphrases must never
    // hand a notification to Windows, which would keep its own copy.
    _applyNotificationPolicy();
    _loadGifPreference();
    _sealOldAttachments();
    Notifications.inApp = showInAppNotice;
    _reloadContacts();
    _reloadGroups();
    _startNetwork(app);
    devices
      ..clear()
      ..add(Device(
        name: 'Tento počítač',
        platform: 'Windows',
        fingerprint: userCode,
        lastSeen: 'právě teď',
        current: true,
      ));
    notifyListeners();
  }

  /// Subscribe to the Rust network layer: Tor bootstrap, our onion address,
  /// peer connect/disconnect, and incoming messages.
  void _startNetwork(UmbraApp app) {
    netStatus = L.t('net.starting');
    app.startNetwork().listen(_onNetEvent, onError: (Object e) {
      lastError = _clean(e);
      netStatus = L.t('net.error');
      notifyListeners();
    });
  }

  /// One event from the Rust network layer.
  void _onNetEvent(NetEvent ev) {
    {
      switch (ev.kind) {
        case 'status':
          netStatus = _render(ev.data);
          break;
        case 'onion':
          onion = ev.data;
          netStatus = L.t('net.online');
          break;
        case 'connected':
          connectedPeers.add(ev.peerHex);
          netStatus = L.t('net.connectedPeer');
          _ensureChat(ev.peerHex);
          break;
        // Which handshake this peer could manage. A conversation that fell back
        // to the classical one has no post-quantum protection, and the person
        // having it should see that rather than assume the newest guarantees.
        case 'wire':
          _ensureChat(ev.peerHex).postQuantum = ev.data == 'hybrid';
          break;
        case 'disconnected':
          connectedPeers.remove(ev.peerHex);
          netStatus = onion.isEmpty ? L.t('net.offline') : L.t('net.online');
          break;
        case 'sent':
          _markSent(ev.peerHex, ev.data);
          pendingMessages = _app?.pendingMessages() ?? 0;
          break;
        case 'delivered':
          _markDelivered(ev.peerHex, ev.data);
          break;
        case 'queued':
          pendingMessages = int.tryParse(ev.data) ?? pendingMessages;
          netStatus = L.t('net.queued');
          break;
        case 'outbox':
          pendingMessages = int.tryParse(ev.data) ?? 0;
          break;
        case 'message':
          _receive(ev.peerHex, ev.data);
          break;
        // Group traffic: the Rust side has already stored (or refused) it, so
        // here we only mirror it into the open UI.
        case 'group_message':
          _receiveGroup(ev.peerHex, ev.data);
          break;
        case 'group_sent':
          _markGroupSent(ev.data);
          break;
        case 'group_invite':
        case 'group_info':
          _reloadGroups();
          break;
        case 'group_removed':
          groups.removeWhere((g) => g.idHex == ev.data);
          break;
        // Rust stored (or updated) the contact row behind this conversation.
        case 'contact_updated':
          final parts = ev.data.split('|');
          final chat = _ensureChat(ev.peerHex);
          if (parts.isNotEmpty && parts[0].isNotEmpty) chat.name = parts[0];
          if (parts.length > 1 && parts[1].isNotEmpty) chat.onion = parts[1];
          if (parts.length > 2) chat.status = int.tryParse(parts[2]) ?? chat.status;
          break;
        case 'profile':
          final chat = _ensureChat(ev.peerHex);
          if (ev.data.isNotEmpty) chat.name = ev.data;
          chat.picturePath = _app?.contactPicturePath(contactHex: ev.peerHex);
          if (chat.picturePath != null && chat.picturePath!.isEmpty) {
            chat.picturePath = null;
          }
          break;
        case 'file_start':
          _fileStart(ev.peerHex, ev.data, incoming: true);
          break;
        case 'file_send_start':
          _fileStart(ev.peerHex, ev.data, incoming: false);
          break;
        case 'file_progress':
        case 'file_send_progress':
          _fileProgress(ev.peerHex, ev.data);
          break;
        case 'file_done':
          _fileDone(ev.peerHex, ev.data);
          break;
        // "label|name|size|storedPath": the label is what the conversation
        // shows, the Rust side has already stored it as a message so it
        // survives a restart, and the path is our own sealed copy so the
        // picture we sent can be shown like the ones we receive.
        case 'file_sent':
          _fileSent(ev.peerHex);
          _addOutgoingAttachment(ev.peerHex, ev.data, pending: false);
          break;
        // The contact was away, so the file (or GIF) sits in the encrypted
        // outbox instead of failing. Show it as waiting, exactly like a text
        // message — otherwise sending a GIF looks like nothing happened.
        case 'file_queued':
          final chat = _ensureChat(ev.peerHex);
          final name = ev.data.split('|').length > 1 ? ev.data.split('|')[1] : ev.data;
          _addOutgoingAttachment(ev.peerHex, ev.data, pending: true);
          showInAppNotice(
            chat.name,
            L.t('file.queued').replaceAll('{name}', name).replaceAll('{who}', chat.name),
          );
          pendingMessages = _app?.pendingMessages() ?? pendingMessages;
          break;
        // The Rust side does the whole update: check over Tor, verify the
        // signature, unpack next to the app. Here we only tell the user.
        case 'update_available':
          // "version|notes", where the notes are what the release published.
          final split = ev.data.indexOf('|');
          updateAvailableVersion = split < 0 ? ev.data : ev.data.substring(0, split);
          updateNotes = split < 0 ? '' : ev.data.substring(split + 1).trim();
          updateStatus =
              L.t('update.available').replaceAll('{v}', updateAvailableVersion ?? '');
          break;
        case 'update_downloading':
          updateDownloading = true;
          updateProgress = null;
          updateStatus = L.t('update.downloading').replaceAll('{v}', ev.data);
          break;
        case 'update_progress':
          final parts = ev.data.split('|');
          final got = int.tryParse(parts.first) ?? 0;
          final total = parts.length > 1 ? int.tryParse(parts[1]) ?? 0 : 0;
          updateDownloading = true;
          updateProgress = total > 0 ? (got / total).clamp(0.0, 1.0) : null;
          // The size comes from the signed manifest when the server does not
          // send one, so "X of Y MB" is there even over Tor's CDN redirects.
          updateStatus = total > 0
              ? '${L.t('update.downloadingPct').replaceAll('{pct}', ((got / total) * 100).round().toString())}'
                  '  ${L.t('update.downloadedOf').replaceAll('{got}', _mb(got)).replaceAll('{total}', _mb(total))}'
              : L.t('update.downloading').replaceAll('{v}', updateAvailableVersion ?? '');
          break;
        case 'update_verifying':
          updateProgress = 1;
          updateStatus = L.t('update.verifying');
          break;
        case 'update_installed':
          updateDownloading = false;
          updateProgress = null;
          updateAvailableVersion = null;
          updateReadyVersion = ev.data;
          updateStatus = L.t('update.ready').replaceAll('{v}', ev.data);
          break;
        case 'update_uptodate':
          if (updateReadyVersion == null) updateStatus = L.t('update.upToDate');
          break;
        case 'update_error':
          updateDownloading = false;
          updateProgress = null;
          // Kept separately from the status line so the dialog can show it in
          // red instead of the user clicking a button that quietly does nothing.
          updateError = ev.data;
          updateStatus = L.t('update.failed').replaceAll('{e}', ev.data);
          break;
        case 'error':
          lastError = _render(ev.data);
          netStatus = lastError!;
          break;
      }
      notifyListeners();
    }
  }

  /// Make sure a chat row exists for a peer that contacted us.
  /// Put a sent file or GIF into the open conversation.
  ///
  /// The row already exists in the database; this is only so the bubble shows
  /// up now instead of after the next sign-in.
  void _addOutgoingAttachment(String peerHex, String data, {required bool pending}) {
    final parts = data.split('|');
    final label = parts.isEmpty ? '' : parts.first;
    if (label.isEmpty) return;
    final name = parts.length > 1 && parts[1].isNotEmpty ? parts[1] : label;
    final size = parts.length > 2 ? int.tryParse(parts[2]) : null;
    final stored = parts.length > 3 && parts[3].isNotEmpty ? parts[3] : null;

    final chat = _ensureChat(peerHex);
    // Guard against the same send producing two bubbles — but match on the
    // stored file, which is unique per send, not on the text. Every GIF the
    // picker sends is called `gif.gif` when the service gives no description,
    // so comparing labels made the second one look like a repeat of the first
    // and nothing appeared at all.
    if (stored != null) {
      for (final m in chat.messages.reversed) {
        if (m.outgoing && m.filePath == stored) {
          m.pending = pending;
          return;
        }
      }
    }
    chat.messages.add(Message(
      label,
      outgoing: true,
      at: DateTime.now(),
      fileName: stored == null ? null : name,
      fileSize: stored == null ? null : size,
    )
      ..pending = pending
      ..filePath = stored
      ..progress = stored == null ? null : 1);
  }

  /// Rebuild a stored message, attachment and all.
  ///
  /// The file part matters: without it a photo or GIF came back from the
  /// database as the line of text describing it, so the preview only ever
  /// existed until the app was closed.
  Message _fromStored(MessageView m) {
    final hasFile = m.filePath.isNotEmpty;
    return Message(
      m.body,
      outgoing: m.outgoing,
      at: DateTime.fromMillisecondsSinceEpoch(m.sentAt.toInt() * 1000),
      // 0 = still in the outbox, 1 = handed over, 2 = confirmed by them.
      pending: m.outgoing && m.state == 0,
      fileName: hasFile ? m.fileName : null,
      fileSize: hasFile ? m.fileSize.toInt() : null,
    )
      ..id = m.id
      ..delivered = m.state == 2
      ..filePath = hasFile ? m.filePath : null
      ..progress = hasFile ? 1 : null;
  }

  /// The conversation with `peerHex`, as the database has it.
  ///
  /// It used to invent one whenever an event mentioned a peer that was not in
  /// the list yet, and a later `contact` event then filled in the name and set
  /// it to accepted. The result was a second tile for somebody already there —
  /// same name, no messages — which is the duplicate-conversation bug as it
  /// survived in the UI after the database side was fixed.
  ///
  /// Now the store decides: a peer it does not know gets a detached object the
  /// caller can write to, but nothing appears in the chat list.
  Chat _ensureChat(String peerHex) {
    final existing = chats.where((c) => c.contactHex == peerHex);
    if (existing.isNotEmpty) return existing.first;

    final known = _app
        ?.listContacts()
        .where((c) => c.identityHex == peerHex)
        .firstOrNull;
    final chat = Chat(
      contactHex: peerHex,
      name: (known == null || known.displayName.isEmpty)
          ? L.t('chats.unknown')
          : known.displayName,
      onion: known?.onion ?? '',
      userCode: known?.userCode ??
          (peerHex.length >= 16 ? peerHex.substring(0, 16).toUpperCase() : peerHex),
    )..status = known?.status ?? 0;
    if (known != null) {
      chat.saved = known.saved;
      chat.verified = known.verified;
      for (final m in _app!.listMessages(contactHex: peerHex, limit: 500)) {
        chat.messages.add(_fromStored(m));
      }
      chats.insert(0, chat);
    }
    return chat;
  }

  /// Conversations the user has accepted.
  List<Chat> get openChats => chats.where((c) => c.status == 1).toList();

  /// People who wrote to us and are waiting for a yes or no.
  List<Chat> get waitingChats => chats.where((c) => c.isWaiting).toList();

  /// The address book: contacts kept on purpose, blocked ones excluded.
  List<Chat> get savedContacts =>
      chats.where((c) => c.saved && !c.isBlocked).toList()
        ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

  List<Chat> get blockedContacts => chats.where((c) => c.isBlocked).toList();

  /// Clear Tor's cached directory data and start the network again. The
  /// identity and onion address survive; only what Tor can re-download goes.
  void repairTor() {
    final app = _app;
    if (app == null) return;
    netStatus = L.t('connecting.repairing');
    notifyListeners();
    try {
      app.repairTor().listen(_onNetEvent, onError: (Object e) {
        lastError = _clean(e);
        netStatus = L.t('net.error');
        notifyListeners();
      });
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Bridge lines the user pasted, empty when NullChat's own list is in use.
  String get customBridges => _app?.customBridges() ?? '';

  /// Save (or, with empty text, drop) the user's own bridges. Tor picks them up
  /// the next time it starts.
  void setCustomBridges(String text) {
    try {
      _app?.setCustomBridges(text: text);
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Let a screen outside this class announce a change it made to the shared
  /// state (which conversation is open, which section is showing).
  void notify() => notifyListeners();

  // --- search ---

  /// Find people, groups and individual messages in one pass.
  ///
  /// Names are matched here (they are already in memory); message text is
  /// matched in Rust, which has to decrypt each body to do it — that is the
  /// price of a database that keeps nothing readable at rest.
  SearchResults search(String rawQuery) {
    final q = rawQuery.trim().toLowerCase();
    if (q.isEmpty) return const SearchResults([], [], []);
    final people = chats
        .where((c) =>
            !c.isBlocked &&
            (c.name.toLowerCase().contains(q) || c.userCode.toLowerCase().contains(q)))
        .toList();
    final matchedGroups =
        groups.where((g) => g.name.toLowerCase().contains(q)).toList();
    var hits = <SearchHitView>[];
    try {
      hits = _app?.searchMessages(query: rawQuery.trim(), limit: 60) ?? [];
    } catch (e) {
      lastError = _clean(e);
    }
    return SearchResults(people, matchedGroups, hits);
  }

  /// Everything one person has sent us, across the 1:1 thread and every group.
  List<SearchHitView> messagesFrom(Chat chat) {
    try {
      return _app?.messagesFromContact(contactHex: chat.contactHex, limit: 300) ?? [];
    } catch (e) {
      lastError = _clean(e);
      return [];
    }
  }

  /// The groups a contact is a member of.
  List<GroupChat> groupsWith(Chat chat) =>
      groups.where((g) => g.members.any((m) => m.identityHex == chat.contactHex)).toList();

  /// Give a contact your own name for them.
  void renameChat(Chat chat, String name) {
    final n = name.trim();
    if (n.isEmpty) return;
    try {
      _app?.renameContact(contactHex: chat.contactHex, name: n);
      chat.name = n;
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  void renameGroup(GroupChat group, String name) {
    final n = name.trim();
    if (n.isEmpty) return;
    try {
      _app?.renameGroup(groupIdHex: group.idHex, name: n);
      group.name = n;
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Accept a waiting conversation, or block the contact for good.
  void setChatStatus(Chat chat, int status) {
    try {
      _app?.setContactStatus(contactHex: chat.contactHex, status: status);
      chat.status = status;
      if (status == 2) {
        // A blocked contact leaves the list entirely; their history stays on
        // disk until they are unblocked.
        chat.saved = false;
        _app?.setContactSaved(contactHex: chat.contactHex, saved: false);
      }
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Keep (or drop) a contact in the address book.
  void setChatSaved(Chat chat, bool saved) {
    try {
      _app?.setContactSaved(contactHex: chat.contactHex, saved: saved);
      chat.saved = saved;
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// An incoming, already-decrypted message from a peer.
  void _receive(String peerHex, String body) {
    final chat = _ensureChat(peerHex);
    final now = DateTime.now();
    chat.messages.add(Message(body, outgoing: false, at: now));
    Notifications.message(
      conversationId: peerHex,
      account: username,
      from: chat.isWaiting ? L.t('waiting.title') : chat.name,
      body: body,
      detailed: Notifications.showContent && autologinEnabled,
      // Someone still waiting for approval does not get to put their text on
      // the user's screen.
      preview: !chat.isWaiting,
    );
    try {
      _app?.addMessage(
        contactHex: peerHex,
        outgoing: false,
        sentAt: BigInt.from(now.millisecondsSinceEpoch ~/ 1000),
        body: body,
      );
    } catch (_) {
      // Storing history must never drop a delivered message.
    }
  }

  /// A file transfer started (either direction): show a placeholder bubble.
  void _fileStart(String peerHex, String data, {required bool incoming}) {
    final parts = data.split('|');
    final name = parts.first;
    final size = parts.length > 1 ? int.tryParse(parts[1]) ?? 0 : 0;
    final chat = _ensureChat(peerHex);
    chat.messages.add(Message(
      name,
      outgoing: !incoming,
      at: DateTime.now(),
      pending: true,
      fileName: name,
      fileSize: size,
    )..progress = 0);
    netStatus = incoming ? L.t('net.receivingFile') : L.t('net.sendingFile');
  }

  void _fileProgress(String peerHex, String data) {
    final parts = data.split('|');
    if (parts.length < 2) return;
    final done = int.tryParse(parts[0]) ?? 0;
    final total = int.tryParse(parts[1]) ?? 0;
    final chat = _ensureChat(peerHex);
    for (final m in chat.messages.reversed) {
      if (m.isFile && m.progress != null && m.progress! < 1) {
        m.progress = total == 0 ? 1 : (done / total).clamp(0, 1).toDouble();
        break;
      }
    }
  }

  /// A received file finished arriving: "path|name|size".
  void _fileDone(String peerHex, String data) {
    final parts = data.split('|');
    final path = parts.first;
    final chat = _ensureChat(peerHex);
    for (final m in chat.messages.reversed) {
      if (m.isFile && !m.outgoing) {
        m.filePath = path;
        m.progress = 1;
        m.pending = false;
        netStatus = onion.isEmpty ? L.t('net.offline') : L.t('net.online');
        return;
      }
    }
    // No bubble was tracking this transfer — it can arrive in one go, or the
    // conversation may have been reloaded meanwhile. The Rust side has already
    // stored it, so show it rather than dropping it on the floor.
    if (parts.length > 1) {
      chat.messages.add(Message(
        '📎 ${parts[1]}',
        outgoing: false,
        at: DateTime.now(),
        fileName: parts[1],
        fileSize: parts.length > 2 ? int.tryParse(parts[2]) : null,
      )
        ..filePath = path
        ..progress = 1);
    }
    netStatus = onion.isEmpty ? L.t('net.offline') : L.t('net.online');
  }

  void _fileSent(String peerHex) {
    final chat = _ensureChat(peerHex);
    for (final m in chat.messages.reversed) {
      if (m.isFile && m.outgoing) {
        m.progress = 1;
        m.pending = false;
        break;
      }
    }
    netStatus = onion.isEmpty ? L.t('net.offline') : L.t('net.online');
  }

  /// Send a file to a contact over the encrypted session.
  void sendFile(Chat chat, String path) {
    _app?.sendFile(contactHex: chat.contactHex, path: path);
    notifyListeners();
  }

  /// Our own profile picture bytes (empty if none).
  Uint8List myPicture() => _app?.myPicture() ?? Uint8List(0);

  /// Set our profile picture; it is stored encrypted and pushed to contacts.
  void setMyPicture(Uint8List bytes) {
    try {
      _app?.setMyPicture(bytes: bytes);
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// A queued message finally went out: stop showing it as pending.
  void _markSent(String peerHex, String body) {
    for (final chat in chats) {
      if (chat.contactHex != peerHex) continue;
      for (final m in chat.messages) {
        if (m.outgoing && m.pending && m.body == body) {
          m.pending = false;
          return;
        }
      }
    }
  }

  /// The peer's app confirmed a message arrived.
  void _markDelivered(String peerHex, String body) {
    for (final chat in chats) {
      if (chat.contactHex != peerHex) continue;
      for (final m in chat.messages) {
        if (m.outgoing && !m.delivered && m.body == body) {
          m.pending = false;
          m.delivered = true;
          return;
        }
      }
    }
  }

  /// Dial a contact over Tor.
  void connectTo(Chat chat) {
    _app?.connectPeer(contactHex: chat.contactHex);
    netStatus = L.t('net.connecting');
    notifyListeners();
  }

  void _reloadContacts() {
    final app = _app;
    if (app == null) return;
    chats.clear();
    for (final c in app.listContacts()) {
      final chat = Chat(
        contactHex: c.identityHex,
        name: c.displayName.isEmpty ? L.t('chats.unknown') : c.displayName,
        onion: c.onion,
        userCode: c.userCode,
      )
        ..status = c.status
        ..saved = c.saved
        ..verified = c.verified;
      for (final m in app.listMessages(contactHex: c.identityHex, limit: 500)) {
        chat.messages.add(_fromStored(m));
      }
      chats.add(chat);
    }
    pendingMessages = app.pendingMessages();
  }

  // --- groups ---

  void _reloadGroups() {
    final app = _app;
    if (app == null) return;
    try {
      final loaded = app.listGroups().map((g) {
        final chat = GroupChat(
          idHex: g.idHex,
          name: g.name,
          members: g.members
              .map((m) => GroupMemberInfo(
                    identityHex: m.identityHex,
                    displayName: m.displayName,
                    onion: m.onion,
                  ))
              .toList(),
        );
        for (final m in app.listGroupMessages(groupIdHex: g.idHex, limit: 500)) {
          chat.messages.add(Message(
            m.body,
            outgoing: m.outgoing,
            at: DateTime.fromMillisecondsSinceEpoch(m.sentAt.toInt() * 1000),
            senderName: m.outgoing ? null : m.senderName,
          ));
        }
        return chat;
      }).toList();
      groups
        ..clear()
        ..addAll(loaded);
    } catch (e) {
      lastError = _clean(e);
    }
  }

  GroupChat? groupById(String idHex) {
    for (final g in groups) {
      if (g.idHex == idHex) return g;
    }
    return null;
  }

  /// Create a group from contacts. The roster is pushed to every member, which
  /// is also how they learn they are in it.
  bool createGroup(String name, List<String> memberHexes) {
    final app = _app;
    if (app == null || name.trim().isEmpty) return false;
    try {
      app.createGroup(
        name: name.trim(),
        memberHexes: memberHexes,
        now: BigInt.from(_nowSecs()),
      );
      _reloadGroups();
      notifyListeners();
      return true;
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
      return false;
    }
  }

  bool addToGroup(GroupChat group, String contactHex) {
    final app = _app;
    if (app == null) return false;
    try {
      app.addGroupMember(groupIdHex: group.idHex, contactHex: contactHex);
      _reloadGroups();
      notifyListeners();
      return true;
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
      return false;
    }
  }

  void leaveGroup(GroupChat group) {
    try {
      _app?.leaveGroup(groupIdHex: group.idHex);
    } catch (e) {
      lastError = _clean(e);
    }
    groups.removeWhere((g) => g.idHex == group.idHex);
    notifyListeners();
  }

  /// Send to a group: stored once, fanned out to each member separately.
  void sendGroupMessage(GroupChat group, String text) {
    final app = _app;
    final t = text.trim();
    if (app == null || t.isEmpty) return;
    final now = DateTime.now();
    try {
      app.sendGroupMessage(
        groupIdHex: group.idHex,
        text: t,
        now: BigInt.from(now.millisecondsSinceEpoch ~/ 1000),
      );
      group.messages.add(Message(
        t,
        outgoing: true,
        at: now,
        // Someone in the group has to be reachable for it to land anywhere.
        pending: !group.members.any((m) => isConnectedTo(m.identityHex)),
      ));
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// `gid|text` from the Rust layer, already persisted there.
  void _receiveGroup(String peerHex, String data) {
    final split = data.indexOf('|');
    if (split <= 0) return;
    final group = groupById(data.substring(0, split));
    if (group == null) {
      _reloadGroups();
      return;
    }
    final sender = group.members.where((m) => m.identityHex == peerHex);
    final senderName = sender.isEmpty ? L.t('chats.unknown') : sender.first.displayName;
    final body = data.substring(split + 1);
    group.messages.add(Message(
      body,
      outgoing: false,
      at: DateTime.now(),
      senderName: senderName,
    ));
    Notifications.message(
      conversationId: group.idHex,
      account: username,
      from: '$senderName (${group.name})',
      body: body,
      detailed: Notifications.showContent && autologinEnabled,
    );
  }

  /// A queued group message reached at least one member.
  void _markGroupSent(String data) {
    final split = data.indexOf('|');
    if (split <= 0) return;
    final group = groupById(data.substring(0, split));
    if (group == null) return;
    final body = data.substring(split + 1);
    for (final m in group.messages) {
      if (m.outgoing && m.pending && m.body == body) {
        m.pending = false;
        return;
      }
    }
  }

  /// Add a contact from a pasted `umbra1:` invite. Returns false on a bad code.
  bool addContactByCode(String raw) {
    final app = _app;
    if (app == null) return false;
    try {
      final c = app.addContact(inviteCode: raw.trim(), now: BigInt.from(_nowSecs()));
      final chat = Chat(
        contactHex: c.identityHex,
        name: c.displayName.isEmpty ? 'Kontakt' : c.displayName,
        onion: c.onion,
        userCode: c.userCode,
      );
      chats.insert(0, chat);
      notifyListeners();
      // Start reaching the contact straight away; the Rust side keeps retrying.
      if (torConnected) connectTo(chat);
      return true;
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
      return false;
    }
  }

  /// Send over the live Tor session. Rust stores the message and, if the peer
  /// is away, keeps it in the encrypted outbox until they come back — so this
  /// works the same whether they are online or not.
  void sendMessage(Chat chat, String text) {
    final app = _app;
    final t = text.trim();
    if (app == null || t.isEmpty) return;
    final now = DateTime.now();
    try {
      app.sendOverNetwork(
        contactHex: chat.contactHex,
        text: t,
        now: BigInt.from(now.millisecondsSinceEpoch ~/ 1000),
      );
      chat.messages.add(Message(
        t,
        outgoing: true,
        at: now,
        pending: !isConnectedTo(chat.contactHex),
      ));
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Restart into the version the updater already put in place.
  Future<void> restartForUpdate() async {
    try {
      await Process.start(
        Platform.resolvedExecutable,
        const [],
        mode: ProcessStartMode.detached,
        workingDirectory: File(Platform.resolvedExecutable).parent.path,
      );
      exit(0);
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// A shareable `umbra1:` invite (empty until our onion address is ready).
  String myInvite() => _app?.myInvite() ?? '';

  // --- duress passphrases (docs/DURESS.md) ---

  /// Which duress passphrases this account has set, e.g. `['decoy']`.
  List<String> get duressConfigured => _app?.duressConfigured() ?? const [];

  /// Add a second passphrase: `'decoy'` or `'wipe'`.
  ///
  /// Setting one also stops NullChat handing notifications to Windows, which keeps
  /// its own copy of them in a database no passphrase of ours can reach.
  String? setDuressPassphrase(String kind, String passphrase) {
    try {
      _app?.setDuressPassphrase(kind: kind, passphrase: passphrase);
      _applyNotificationPolicy();
      notifyListeners();
      return null;
    } catch (e) {
      return _clean(e);
    }
  }

  /// Turn one off again. Needs the passphrase itself — nothing else can reach
  /// its rows.
  String? clearDuressPassphrase(String passphrase) {
    try {
      _app?.clearDuressPassphrase(passphrase: passphrase);
      _applyNotificationPolicy();
      notifyListeners();
      return null;
    } catch (e) {
      return _clean(e);
    }
  }

  /// Put a believable conversation into the decoy account.
  String? fillDecoy(String passphrase, String contactName, List<String> lines) {
    try {
      _app?.fillDecoy(
        passphrase: passphrase,
        contactName: contactName,
        lines: lines,
        startAt: BigInt.from(
            DateTime.now().subtract(const Duration(days: 40)).millisecondsSinceEpoch ~/ 1000),
      );
      notifyListeners();
      return null;
    } catch (e) {
      return _clean(e);
    }
  }

  /// An account with duress passphrases must not leave notifications in the
  /// operating system's own history, so NullChat draws them itself instead.
  void _applyNotificationPolicy() {
    Notifications.useSystemNotifications = duressConfigured.isEmpty;
  }

  /// A notice NullChat draws itself. Cleared after a few seconds.
  ({String title, String body})? inAppNotice;
  int _noticeSeq = 0;

  void showInAppNotice(String title, String body) {
    inAppNotice = (title: title, body: body);
    final seq = ++_noticeSeq;
    notifyListeners();
    Future.delayed(const Duration(seconds: 6), () {
      if (_noticeSeq == seq) {
        inAppNotice = null;
        notifyListeners();
      }
    });
  }

  // --- GIFs (docs/GIFS.md) ---

  /// Whether the user has agreed to GIF search reaching an outside service.
  ///
  /// Off until they say otherwise: everything else in NullChat contacts nobody,
  /// so starting to contact somebody is their decision to make.
  bool gifsEnabled = false;
  File? _gifPrefFile;

  Future<void> _loadGifPreference() async {
    try {
      final dir = await AppDir.path();
      _gifPrefFile = File('$dir${Platform.pathSeparator}gifs-enabled.txt');
      if (await _gifPrefFile!.exists()) {
        gifsEnabled = (await _gifPrefFile!.readAsString()).trim() == '1';
      }
    } catch (_) {}
  }

  Future<void> setGifsEnabled(bool value) async {
    gifsEnabled = value;
    try {
      await _gifPrefFile?.writeAsString(value ? '1' : '0');
    } catch (_) {}
    notifyListeners();
  }

  /// The account's own GIPHY API key, when they set one. Released builds ship
  /// with a key, so this is normally empty and nobody has to care.
  String get gifKey => _app?.gifKey() ?? '';

  /// Released builds ship with a key, so this is normally true and nobody is
  /// asked to set anything up.
  bool get gifKeyAvailable => _app?.gifKeyAvailable() ?? false;

  Future<void> setGifKey(String key) async {
    _app?.setGifKey(key: key.trim());
    notifyListeners();
  }

  /// Search, through Tor. An empty query returns what is popular.
  Future<List<GifView>> gifSearch(String query) async {
    final app = _app;
    if (app == null) return const [];
    return app.gifSearch(query: query, limit: 30);
  }

  /// A preview thumbnail, fetched through Tor rather than by the image widget.
  Future<Uint8List> gifPreview(String url) async {
    final app = _app;
    if (app == null) throw Exception(L.t('net.notRunning'));
    return app.gifPreview(url: url);
  }

  /// Send one. We download it and push the bytes through the encrypted file
  /// channel, so the recipient never contacts the GIF service.
  void sendGif(String contactHex, GifView gif) {
    try {
      _app?.sendGif(
        contactHex: contactHex,
        gifUrl: gif.gifUrl,
        description: gif.description,
      );
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Send the same message to somebody else.
  ///
  /// A file is forwarded from our own sealed copy, so it is never fetched from
  /// wherever it came from a second time.
  void forwardMessage(Chat to, Message msg) {
    final app = _app;
    if (app == null) return;
    try {
      if (msg.filePath != null) {
        app.forwardAttachment(
          contactHex: to.contactHex,
          path: msg.filePath!,
          name: msg.fileName ?? 'file',
        );
      } else {
        sendMessage(to, msg.body);
      }
    } catch (e) {
      lastError = _clean(e);
    }
    notifyListeners();
  }

  /// Remove one message from this device.
  ///
  /// Local only, and the UI says so: the copy the other side holds is theirs.
  void deleteMessage(Chat chat, Message msg) {
    final app = _app;
    if (app != null && msg.id != null) {
      try {
        app.deleteMessage(id: msg.id!);
      } catch (e) {
        lastError = _clean(e);
      }
    }
    chat.messages.remove(msg);
    if (msg.filePath != null) _attachmentCache.remove(msg.filePath);
    notifyListeners();
  }

  /// Attachment bytes, decrypted into memory for the preview.
  ///
  /// Nothing readable is written to disk: the sealed file stays sealed and the
  /// plaintext lives only as long as the widget showing it. Results are cached
  /// so scrolling past a photo does not decrypt it again, and the cache is
  /// small on purpose — it holds decrypted personal content.
  final Map<String, Uint8List> _attachmentCache = {};
  static const int _attachmentCacheMax = 8;

  Future<Uint8List?> attachmentBytes(String storedPath) async {
    final cached = _attachmentCache[storedPath];
    if (cached != null) return cached;
    final app = _app;
    if (app == null) return null;
    try {
      final bytes = await app.readAttachment(path: storedPath);
      if (_attachmentCache.length >= _attachmentCacheMax) {
        _attachmentCache.remove(_attachmentCache.keys.first);
      }
      _attachmentCache[storedPath] = bytes;
      return bytes;
    } catch (_) {
      return null;
    }
  }

  /// Forget decrypted attachments; called when the account is closed so they do
  /// not outlive the session that was allowed to see them.
  void _clearAttachmentCache() => _attachmentCache.clear();

  /// Decrypt an attachment to wherever the user picks.
  ///
  /// Attachments live sealed on disk, so this is the only path by which a
  /// readable copy is created — and it happens because somebody chose where.
  Future<void> saveAttachment(String storedPath, String suggestedName) async {
    final app = _app;
    if (app == null) return;
    try {
      final to = await FilePicker.saveFile(
        dialogTitle: L.t('chat.saveFile'),
        fileName: suggestedName,
      );
      if (to == null) return; // cancelled
      await app.exportAttachment(path: storedPath, to: to);
      lastError = null;
    } catch (e) {
      lastError = _clean(e);
    }
    notifyListeners();
  }

  /// Seal attachments an older version left readable on disk.
  Future<void> _sealOldAttachments() async {
    try {
      final n = await _app?.encryptExistingAttachments() ?? 0;
      if (n > 0) {
        // Worth saying out loud: their files just changed on disk.
        showInAppNotice(
          L.t('files.sealedTitle'),
          L.t('files.sealedBody').replaceAll('{n}', n.toString()),
        );
      }
    } catch (_) {
      // Never block sign-in on this.
    }
  }

  /// Fold [from] into [into]: the same person under two identities. The
  /// messages move, nothing is deleted, and the thread that stays is the one
  /// the user is still writing to.
  void mergeChats(Chat from, Chat into) {
    try {
      final moved = _app?.mergeContact(
            fromHex: from.contactHex,
            intoHex: into.contactHex,
          ) ??
          0;
      _reloadContacts();
      selectedChat = chats.firstWhere(
        (c) => c.contactHex == into.contactHex,
        orElse: () => into,
      );
      showInAppNotice(
        into.name,
        L.t('merge.done').replaceAll('{n}', moved.toString()),
      );
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// Remove a contact and its conversation, here and in the encrypted store.
  void deleteChat(Chat chat) {
    try {
      _app?.deleteContact(contactHex: chat.contactHex);
      chats.removeWhere((c) => c.contactHex == chat.contactHex);
      if (selectedChat?.contactHex == chat.contactHex) selectedChat = null;
      notifyListeners();
    } catch (e) {
      lastError = _clean(e);
      notifyListeners();
    }
  }

  /// The 60 digits this contact and I must both read, in groups of five.
  String safetyNumber(String contactHex) =>
      _app?.safetyNumber(contactHex: contactHex) ?? '';

  /// Whether this contact's identity is signed post-quantum as well.
  bool contactIsPostQuantum(String contactHex) =>
      _app?.contactIsPostQuantum(contactHex: contactHex) ?? false;

  /// Record the user's own answer to "did the numbers match?".
  ///
  /// This used to flip a flag that lived only in memory and was never shown,
  /// so nothing was ever verified. Now it is stored with the contact.
  void setVerified(Chat chat, bool verified) {
    try {
      _app?.setVerified(contactHex: chat.contactHex, verified: verified);
      chat.verified = verified;
    } catch (e) {
      lastError = _clean(e);
    }
    notifyListeners();
  }

  void setPaddingFloor(int index) {
    paddingFloorIndex = index;
    notifyListeners();
  }

  void revokeDevice(Device d) {
    d.revoked = true;
    notifyListeners();
  }

  static String _group(String hex) {
    final take = hex.length >= 32 ? hex.substring(0, 32) : hex;
    final groups = <String>[];
    for (var i = 0; i < take.length; i += 4) {
      groups.add(take.substring(i, i + 4 > take.length ? take.length : i + 4));
    }
    return groups.join(' ');
  }

  /// Turn a status/error code from Rust into a sentence in the chosen language.
  static String _render(String code) {
    if (code == 'tor_starting') return L.t('net.torStarting');
    if (code == 'queued') return L.t('net.queued');
    if (code == 'stale_invite') return L.t('net.staleInvite');
    if (code == 'net_not_running') return L.t('net.notRunning');
    if (code.startsWith('connecting|')) {
      final p = code.split('|');
      return L
          .t('net.attempt')
          .replaceAll('{a}', p.length > 1 ? p[1] : '?')
          .replaceAll('{b}', p.length > 2 ? p[2] : '?');
    }
    if (code.startsWith('unreachable|')) {
      return L.t('net.unreachable').replaceAll('{e}', code.substring(12));
    }
    return code; // Tor's own bootstrap lines and anything else pass through
  }

  static String _clean(Object e) {
    var s = e.toString();
    if (s.startsWith('Exception: ')) s = s.substring(11);
    return s;
  }

  /// Bytes as megabytes with one decimal — the unit an update is measured in.
  static String _mb(int bytes) => (bytes / (1024 * 1024)).toStringAsFixed(1);
}

final AppState appState = AppState();
