// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Minimal two-language support. English is the default so the app is usable by
// anyone who receives it; Czech can be switched on in Settings and the choice
// is remembered next to the app's data.

import 'dart:io';

import 'app_dir.dart';

import 'package:flutter/foundation.dart';

/// Notifies the whole app when the language changes.
final ValueNotifier<String> languageNotifier = ValueNotifier<String>('en');

class L {
  static String _lang = 'en';
  static File? _file;

  static String get lang => _lang;

  /// Load the stored preference (call once at startup).
  static Future<void> load() async {
    try {
      final dir = Directory(await AppDir.path());
      _file = File('${dir.path}${Platform.pathSeparator}language.txt');
      if (await _file!.exists()) {
        final v = (await _file!.readAsString()).trim();
        if (_strings.containsKey(v)) {
          _lang = v;
          languageNotifier.value = v;
        }
      }
    } catch (_) {
      // Preference is a nicety; never block startup on it.
    }
  }

  static Future<void> set(String lang) async {
    if (!_strings.containsKey(lang)) return;
    _lang = lang;
    languageNotifier.value = lang;
    try {
      await _file?.writeAsString(lang);
    } catch (_) {}
  }

  /// Translate a key; falls back to English, then to the key itself.
  static String t(String key) =>
      _strings[_lang]?[key] ?? _strings['en']![key] ?? key;

  static const Map<String, Map<String, String>> _strings = {
    'en': {
      'app.tagline': 'Encrypted peer-to-peer messaging.\nNo server, no traces.',
      'app.experimental':
          'Experimental. Not audited yet — do not bet your life on it.',
      'onboard.create.title': 'Create your identity',
      'onboard.create.subtitle':
          'Your account is a key on this computer, protected by this passphrase. It is never sent anywhere.',
      'onboard.unlock.title': 'Unlock your identity',
      'onboard.unlock.subtitle': 'Enter your passphrase.',
      'onboard.username': 'Username',
      'onboard.passphrase': 'Passphrase (min. 12 characters)',
      'onboard.passHelp':
          'Four ordinary words you will remember beat eight clever characters. Nobody can reset this: whoever has the database file can try guesses forever, and there is no server to stop them.',
      'onboard.strength0': 'too short',
      'onboard.strength1': 'weak',
      'onboard.strength2': 'fair',
      'onboard.strength3': 'good',
      'onboard.strength4': 'strong',
      'onboard.repeat': 'Repeat passphrase',
      'onboard.create.button': 'Create identity',
      'onboard.unlock.button': 'Unlock',
      'onboard.forgot': 'Forgot passphrase — create a new identity',
      'nav.chats': 'Chats',
      'nav.devices': 'Devices',
      'nav.settings': 'Settings',
      'nav.profile': 'Profile',
      'gif.tooltip': 'Send a GIF',
      'gif.search': 'Search GIFs…',
      'gif.loading': 'Loading over Tor…',
      'gif.none': 'Nothing found',
      'gif.viaTor': 'Searching through Tor, on a separate circuit.',
      'gif.enableTitle': 'Turn on GIF search?',
      'gif.enableBody':
          'GIFs come from Tenor, which is Google\'s. Searching sends your search '
          'terms there — through Tor, on a circuit of its own, so they learn a '
          'search term but not who you are, where you are, or who you are '
          'talking to. Everything else in NullChat contacts nobody, so this is '
          'yours to decide.',
      'gif.enableProtected':
          'The person you send a GIF to never contacts Tenor: NullChat downloads '
          'it and sends the file to them encrypted, like any other attachment. '
          'They cannot be tracked by receiving it.',
      'gif.enableYes': 'Turn on',
      'gif.enableNo': 'No thanks',
      'connecting.title': 'Connecting to Tor',
      'connecting.subtitle':
          'NullChat needs a Tor connection before it can reach anyone. Nothing here needs your attention — it just takes a while.',
      'connecting.hint':
          'The first start can take 2–15 minutes: Tor downloads the network directory, and on networks that block Tor it looks for a way through bridges. Later starts are much faster.',
      'chats.title': 'Chats',
      'chats.subtitle': 'Direct end-to-end conversations',
      'chats.add': 'Add',
      'chats.empty': 'No messages yet',
      'chats.unknown': 'Unknown contact',
      'chats.pickOne': 'Pick a conversation on the left',
      'chat.connect': 'Connect',
      'chat.connected': 'Connected',
      'chat.verified': 'Verified',
      'chat.unverified': 'Not verified',
      'safety.title': 'Safety number with {name}',
      'safety.how':
          'Read these 60 digits to each other — over a phone call where you know '
          'the voice, or standing next to each other. If they match on both '
          'screens, nobody is sitting in the middle of this conversation.',
      'safety.warning':
          'Until you have compared them, everything is encrypted, but there is '
          'no proof the invite you used really came from this person. Compare '
          'all of the digits: checking a few is not almost as good.',
      'safety.isVerified':
          'You confirmed these digits matched. If they ever change, the person '
          'reinstalled NullChat or someone is impersonating them — compare again.',
      'wire.legacy': 'Older version',
      'wire.legacyHelp':
          'This contact runs a version from before post-quantum identities, so '
          'this conversation is signed with Ed25519 alone. It is still '
          'end-to-end encrypted. Ask them to update, then swap invites again.',
      'safety.pq':
          'This identity is post-quantum: signed with Ed25519 and ML-DSA-65 '
          'together, so a quantum computer could not impersonate them even '
          'after breaking the classical half.',
      'safety.noPq':
          'This contact was added before post-quantum identities and is '
          'protected by Ed25519 alone. Swap invites again once you both run '
          '1.9.0 or later.',
      'safety.confirm': 'The numbers match',
      'safety.unverify': 'Undo verification',
      'chat.verify': 'Verify',
      'chat.compose': 'Write a message…',
      'chat.attach': 'Send a file (encrypted)',
      'chat.showFile': 'Show in folder',
      'settings.picture': 'Profile picture',
      'settings.pickPicture': 'Choose picture',
      'settings.removePicture': 'Remove',
      'chat.pending': 'waiting to connect',
      'chat.waiting': 'waiting for them',
      'chat.today': 'Today',
      'chat.yesterday': 'Yesterday',
      'chats.emptyTitle': 'No conversations yet',
      'chats.emptyHelp':
          'Send someone your invite, or paste theirs. NullChat has no user directory — a conversation starts only because you two chose it.',
      'chat.sent': 'sent',
      'chat.outbox': '{n} waiting — they go out as soon as {name} is online.',
      'chat.outboxOne': '1 waiting — it goes out as soon as {name} is online.',
      'net.notStarted': 'Network not started',
      'net.starting': 'Starting Tor…',
      'net.online': 'Online via Tor',
      'net.offline': 'Offline',
      'net.connectedPeer': 'Connected to contact',
      'net.connecting': 'Connecting…',
      'net.queued': 'Message waiting for a connection',
      'net.receivingFile': 'Receiving file…',
      'net.sendingFile': 'Sending file…',
      'net.error': 'Network error',
      'net.torStarting': 'Connecting to the Tor network…',
      'net.attempt': 'Connecting… (attempt {a} of {b} — this takes a while over Tor)',
      'net.unreachable': 'Contact not reachable yet: {e}',
      'net.staleInvite':
          'That invite is out of date: the contact now has a different identity. Ask them for a new invite and add them again.',
      'net.notRunning': 'The network is not running yet',
      'chat.delivered': 'delivered',
      'add.title': 'Add contact',
      'add.help':
          'Paste your contact\'s INVITE — the long text starting with "umbra1:".\nThey get it in Settings via "Copy invite".',
      'add.help2':
          'A name or short code is not enough — the invite also carries the address where the contact can be reached.',
      'add.paste': 'Paste from clipboard',
      'add.cancel': 'Cancel',
      'add.submit': 'Add',
      'add.notInvite':
          'That is not an invite. You need the whole text starting with "umbra1:", which your contact copies in Settings.',
      'add.failed': 'The invite could not be read.',
      'add.ok': 'Contact added — open the chat and connect',
      'settings.title': 'Settings',
      'settings.yourCode': 'Your code — share it so people can find you',
      'settings.copyCode': 'Copy code',
      'settings.codeCopied': 'Code copied',
      'settings.copyInvite': 'Copy invite',
      'settings.inviteNotReady': 'Invite will be ready once Tor connects',
      'settings.inviteCopied': 'Invite copied — send it to your contact',
      'settings.network': 'Network (Tor onion service)',
      'settings.online': 'Online',
      'settings.offline': 'Offline',
      'settings.copyOnion': 'Copy onion address',
      'settings.onionCopied': 'Onion address copied',
      'settings.padding': 'Length hiding (padding)',
      'settings.paddingHelp':
          'Every message is padded to a fixed size so nothing can be read from its length.',
      'settings.language': 'Language',
      'update.title': 'Version',
      'update.available': 'Version {v} is out.',
      'update.dialogTitle': 'New version {v}',
      'update.dialogBody':
          'It is downloaded over Tor and installed only if it is signed by the author. Your messages, contacts and history stay untouched.',
      'update.install': 'Update',
      'update.retry': 'Try again',
      'update.later': 'Later',
      'update.whatsNew': 'What changed',
      'update.workingTitle': 'Updating…',
      'update.starting': 'Starting the download over Tor…',
      'update.downloadingPct': 'Downloading over Tor… {pct} %',
      'update.downloadedOf': '({got} of {total} MB)',
      'update.verifying': 'Checking the signature…',
      'update.checking': 'Checking for updates over Tor…',
      'update.upToDate': 'You are on the newest version.',
      'update.downloading': 'Downloading version {v}…',
      'update.ready': 'Version {v} is installed — restart to use it.',
      'update.failed': 'Update did not happen: {e}',
      'update.restart': 'Restart',
      'update.banner': 'A new version ({v}) is ready.',
      'groups.create': 'New group',
      'groups.createButton': 'Create group',
      'groups.name': 'Group name',
      'groups.pick': 'Who is in it',
      'groups.noContacts': 'Add a contact first — a group is built from contacts.',
      'groups.noCandidates': 'Every contact of yours is already in this group.',
      'groups.addMember': 'Add member',
      'groups.leave': 'Leave group',
      'groups.leaveTitle': 'Leave this group?',
      'groups.leaveBody':
          'The others are told you left, and this group and its history are erased on this computer.',
      'groups.memberLine': '{n} members • {online} online',
      'groups.you': 'You',
      'groups.onlineOnly':
          'A group message reaches the members who are online right now — there is no server to hold it.',
      'settings.autostart': 'Start with Windows',
      'settings.autostartHelp':
          'NullChat launches when you sign in, so you are reachable without opening it by hand.',
      'settings.autostartFailed': 'Windows did not accept the change.',
      'settings.theme': 'Colour theme',
      'settings.themeHelp':
          'Pick one of the built-in themes, or mix your own colour — the whole app follows it.',
      'settings.themeCustom': 'Custom colour',
      'settings.themeCustomTitle': 'Your own colour',
      'settings.themeHue': 'Hue',
      'settings.themeSaturation': 'Intensity',
      'settings.themePreview': 'Preview',
      'theme.mint': 'Mint',
      'theme.azure': 'Azure',
      'theme.violet': 'Violet',
      'theme.amber': 'Amber',
      'theme.rose': 'Rose',
      'theme.day': 'Daylight',
      'theme.custom': 'Custom',
      'settings.disclaimer':
          'NullChat is experimental and has not been independently audited. Do not rely on it where lives are at stake.',
      'devices.title': 'Devices',
      'devices.subtitle': 'active • signed by your key, revocable',
      'devices.fingerprint': 'Your identity fingerprint',
      'devices.thisDevice': 'This device',
      'devices.revoked': 'Revoked',
      'devices.revoke': 'Revoke',
      'devices.lastSeen': 'last seen',
      'devices.revokeTitle': 'Revoke device?',
      'devices.revokeBody':
          'This device will lose access. A signed revocation is sent to your contacts so they stop trusting it.',
      'accounts.title': 'Choose an account',
      'accounts.subtitle': 'Each account has its own identity, contacts and history.',
      'accounts.add': 'New account',
      'accounts.unnamed': 'Unnamed account',
      'accounts.autoOn': 'Signs in automatically',
      'accounts.autoOff': 'Asks for the passphrase',
      'accounts.remember': 'Sign in automatically on this computer',
      'accounts.rememberHelp':
          'The passphrase is stored encrypted for your Windows user. Anyone who can use your Windows account can then open this account.',
      'accounts.back': 'Back to accounts',
      'accounts.remove': 'Delete',
      'accounts.removeTitle': 'Delete this account?',
      'accounts.removeBody':
          'its identity, contacts and message history on this computer are erased. This cannot be undone.',
      'accounts.switch': 'Switch account',
      'accounts.signOut': 'Sign out',
      'accounts.createTitle': 'New account',
      'common.cancel': 'Cancel',
      'common.save': 'Save',
      'common.close': 'Close',
      'duress.title': 'Emergency passphrases',
      'duress.intro':
          'This account can answer to more than one passphrase. Set neither, '
          'one, or both — nothing in the file records how many there are, and '
          'NullChat behaves identically whichever you type.',
      'duress.decoy.title': 'Decoy account',
      'duress.decoy.body':
          'Opens a separate history with its own contacts and messages. Your '
          'real conversations are not hidden from view — they are unreachable '
          'from it, and searching finds nothing of them. Fill it with ordinary '
          'conversation so it does not look staged.',
      'duress.wipe.title': 'Destroy on entry',
      'duress.wipe.body':
          'Destroys everything it cannot read and then opens as a brand-new '
          'account. This cannot be undone and there is no confirmation — that '
          'is the point. The file keeps its size, so nothing about it looks '
          'freshly emptied.',
      'duress.set': 'Set',
      'duress.none': 'None set — one passphrase opens this account',
      'duress.count': '{n} set',
      'duress.setUp': 'Set up',
      'duress.remove': 'Remove',
      'duress.fill': 'Fill with conversation',
      'duress.pickHint':
          'At least 12 characters, and different from your real one. Pick '
          'something you can type calmly under pressure without thinking.',
      'duress.newPhrase': 'Emergency passphrase',
      'duress.repeat': 'Type it again',
      'duress.mismatch': 'The two entries are not the same.',
      'duress.removeHint':
          'Type the emergency passphrase you want to remove. It is the only '
          'thing that can reach what it created.',
      'duress.thatPhrase': 'That emergency passphrase',
      'duress.decoyPhrase': 'Decoy passphrase',
      'duress.fillHint':
          'Written into the decoy account, spread over the past weeks. Add a '
          'few conversations, and open the decoy occasionally — a history whose '
          'every message was written in one afternoon convinces nobody.',
      'duress.fillWho': "The other person's name",
      'duress.fillLines': 'One message per line (alternating sides)',
      'duress.fillEmpty': 'Enter a name and at least one message.',
      'duress.fillDone': 'Added {n} messages.',
      'duress.limits.title': 'Where this stops working',
      'duress.limits.body':
          'It cannot help against anyone who copied the disk BEFORE you typed '
          'the passphrase — comparing the two copies shows what changed, and '
          'nothing running afterwards can prevent that. It cannot hide a decoy '
          'that is obviously empty, a passphrase of a visibly different length, '
          'or traces left elsewhere on the computer: the Windows page file, '
          'backup software, or thumbnails.',
      'duress.notifications':
          'Notifications are no longer handed to Windows while an emergency '
          'passphrase is set. Windows keeps its own copy of every notice it '
          'shows, in a database no passphrase of ours can reach, so NullChat now '
          'draws them itself inside its own window.',
      'waiting.title': 'Waiting for you',
      'waiting.help':
          'People you have not talked to before. Read what they wrote, then let them in or block them.',
      'waiting.accept': 'Accept',
      'waiting.block': 'Block',
      'contacts.title': 'Contacts',
      'contacts.subtitle': 'People you keep — pick them when building a group.',
      'search.hint': 'Search people, groups and messages',
      'search.people': 'People',
      'search.groups': 'Groups',
      'search.messages': 'Messages',
      'search.inGroup': 'group',
      'search.none': 'Nothing matches “{q}”.',
      'contact.where': 'Where you talk',
      'contact.messages': 'What they wrote',
      'contact.directChat': 'Direct conversation',
      'contact.sharedGroups': 'Groups you share',
      'contact.noGroups': 'You are not in a group with this person.',
      'contact.noMessages': 'Nothing from this person yet.',
      'contact.all': 'Everything',
      'contact.direct': 'Direct only',
      'contact.fromGroups': 'From groups',
      'chats.new': 'New',
      'contacts.empty':
          'No saved contacts yet. Save someone from a conversation and they show up here.',
      'contacts.blocked': 'Blocked',
      'contacts.rename': 'Rename',
      'contacts.newName': 'New name',
      'contacts.save': 'Save to contacts',
      'contacts.forget': 'Remove from contacts',
      'contacts.unblock': 'Unblock',
      'contacts.delete': 'Delete conversation',
      'contacts.deleteBody':
          'Removes {name} and all {n} messages with them from this device. This '
          'cannot be undone — the messages are erased from the encrypted store, '
          'not moved to a bin. The other person keeps their own copy.',
      'groups.rename': 'Rename group',
      'notif.message': 'New message',
      'notif.newFor': 'New message on @{account}',
      'notif.title': 'Notifications',
      'notif.detail': 'Show sender and message text',
      'notif.detailHelp':
          'Notifications will read "sender → account: message" instead of just announcing that something arrived.',
      'notif.detailLocked':
          'Only for accounts that sign in automatically. This one asks for the passphrase every time, so its messages stay off an unattended screen.',
      'notif.example': 'A notification will look like: {example}',
      'notif.exampleFrom': 'Eva',
      'notif.exampleBody': 'see you at six',
      'connecting.repair': 'Repair and try again',
      'connecting.repairHelp':
          'Deletes what Tor downloaded about the network and starts over. Your identity, address and messages are untouched.',
      'connecting.repairing': 'Repairing Tor and reconnecting…',
      'bridges.title': 'Tor bridges',
      'bridges.usingDefault': 'Using the bridges NullChat ships with.',
      'bridges.usingCustom': 'Using your own bridges.',
      'bridges.help':
          'The bundled bridges are public, so a censor can block them. If Tor will not connect, get personal bridges from bridges.torproject.org (or e-mail bridges@torproject.org) and paste the lines here.',
      'bridges.hint': 'obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0',
      'bridges.saved': 'Saved — takes effect on the next start.',
      'licenses.title': 'Licences',
      'licenses.subtitle': 'What NullChat is built from, and under what terms.',
      'licenses.header': 'NullChat is AGPL-3.0. Everything it uses is listed here.',
      'licenses.full':
          'The complete list of every dependency, including the ones pulled in indirectly, is in THIRD-PARTY.md next to the source.',
      'licenses.packages': 'Package licence texts',
      'tray.open': 'Open NullChat',
      'tray.quit': 'Quit (you stop being reachable)',
      'settings.trayHint':
          'Closing the window leaves NullChat running in the tray so messages keep arriving. Quit from the tray icon.',
    },
    'cs': {
      'app.tagline': 'Šifrovaná peer-to-peer komunikace.\nŽádný server, žádné stopy.',
      'app.experimental':
          'Experimentální. Zatím bez auditu — nespoléhej na to životem.',
      'onboard.create.title': 'Vytvoř si identitu',
      'onboard.create.subtitle':
          'Účet je klíč v tomto počítači, chráněný touto frází. Nikam se neposílá.',
      'onboard.unlock.title': 'Odemkni svou identitu',
      'onboard.unlock.subtitle': 'Zadej svou přístupovou frázi.',
      'onboard.username': 'Uživatelské jméno',
      'onboard.passphrase': 'Přístupová fráze (min. 12 znaků)',
      'onboard.passHelp':
          'Čtyři obyčejná slova, která si zapamatuješ, jsou lepší než osm chytrých znaků. Nejde ji resetovat: kdo má soubor s databází, může hádat donekonečna a není server, který by ho zastavil.',
      'onboard.strength0': 'krátká',
      'onboard.strength1': 'slabá',
      'onboard.strength2': 'ujde',
      'onboard.strength3': 'dobrá',
      'onboard.strength4': 'silná',
      'onboard.repeat': 'Zopakuj frázi',
      'onboard.create.button': 'Vytvořit identitu',
      'onboard.unlock.button': 'Odemknout',
      'onboard.forgot': 'Zapomenutá fráze — založit novou identitu',
      'nav.chats': 'Chaty',
      'nav.devices': 'Zařízení',
      'nav.settings': 'Nastavení',
      'nav.profile': 'Profil',
      'gif.tooltip': 'Poslat GIF',
      'gif.search': 'Hledat GIFy…',
      'gif.loading': 'Načítám přes Tor…',
      'gif.none': 'Nic nenalezeno',
      'gif.viaTor': 'Hledá se přes Tor, samostatným okruhem.',
      'gif.enableTitle': 'Zapnout hledání GIFů?',
      'gif.enableBody':
          'GIFy jsou z Tenoru, což je Google. Hledání tam posílá, co hledáš — '
          'přes Tor a vlastním okruhem, takže se dozvědí hledaný výraz, ale ne '
          'kdo jsi, kde jsi, ani s kým si píšeš. Všechno ostatní v NullChatu '
          'nekontaktuje nikoho, takže tohle je tvoje rozhodnutí.',
      'gif.enableProtected':
          'Ten, komu GIF pošleš, s Tenorem nikdy nemluví: NullChat ho stáhne a '
          'pošle mu ho zašifrovaně jako každou jinou přílohu. Tím, že ho '
          'dostane, ho nikdo nevystopuje.',
      'gif.enableYes': 'Zapnout',
      'gif.enableNo': 'Ne, díky',
      'connecting.title': 'Připojuji se k Toru',
      'connecting.subtitle':
          'NullChat potřebuje spojení se sítí Tor, než na někoho dosáhne. Nic nemusíš dělat — jen to chvíli trvá.',
      'connecting.hint':
          'První spuštění může trvat 2–15 minut: Tor stahuje adresář sítě a na sítích, které ho blokují, hledá cestu přes mosty. Další spuštění jsou výrazně rychlejší.',
      'chats.title': 'Chaty',
      'chats.subtitle': 'Přímé end-to-end konverzace',
      'chats.add': 'Přidat',
      'chats.empty': 'Zatím žádné zprávy',
      'chats.unknown': 'Neznámý kontakt',
      'chats.pickOne': 'Vlevo si vyber konverzaci',
      'chat.connect': 'Připojit',
      'chat.connected': 'Spojeno',
      'chat.verified': 'Ověřeno',
      'chat.unverified': 'Neověřeno',
      'safety.title': 'Bezpečnostní číslo s {name}',
      'safety.how':
          'Přečtěte si těchto 60 číslic navzájem — po telefonu, kde poznáš hlas, '
          'nebo osobně vedle sebe. Když se na obou obrazovkách shodují, nikdo '
          'nesedí uprostřed vaší konverzace.',
      'safety.warning':
          'Dokud je neporovnáte, je sice všechno šifrované, ale nic nedokazuje, '
          'že pozvánka opravdu přišla od tohoto člověka. Porovnejte všechny '
          'číslice — zkontrolovat jen pár není skoro stejně dobré.',
      'safety.isVerified':
          'Potvrdil jsi, že se číslice shodovaly. Pokud se někdy změní, buď si '
          'ten člověk přeinstaloval Umbru, nebo se za něj někdo vydává — '
          'porovnejte je znovu.',
      'wire.legacy': 'Starší verze',
      'wire.legacyHelp':
          'Tento kontakt má verzi z doby před post-kvantovými identitami, takže '
          'je tahle konverzace podepsaná jen Ed25519. Pořád je end-to-end '
          'šifrovaná. Řekni mu, ať aktualizuje, a pak si vyměňte pozvánky znovu.',
      'safety.pq':
          'Tato identita je post-kvantová: podepsaná Ed25519 a ML-DSA-65 '
          'zároveň, takže se za ni kvantový počítač nevydá ani po prolomení '
          'té klasické poloviny.',
      'safety.noPq':
          'Tento kontakt byl přidán před post-kvantovými identitami a chrání '
          'ho jen Ed25519. Až budete oba mít 1.9.0 nebo novější, vyměňte si '
          'pozvánky znovu.',
      'safety.confirm': 'Čísla se shodují',
      'safety.unverify': 'Zrušit ověření',
      'chat.verify': 'Ověřit',
      'chat.compose': 'Napiš zprávu…',
      'chat.attach': 'Poslat soubor (šifrovaně)',
      'chat.showFile': 'Zobrazit ve složce',
      'settings.picture': 'Profilový obrázek',
      'settings.pickPicture': 'Vybrat obrázek',
      'settings.removePicture': 'Odebrat',
      'chat.pending': 'čeká na spojení',
      'chat.waiting': 'čeká na protějšek',
      'chat.today': 'Dnes',
      'chat.yesterday': 'Včera',
      'chats.emptyTitle': 'Zatím žádné konverzace',
      'chats.emptyHelp':
          'Pošli někomu svoji pozvánku, nebo vlož jeho. NullChat nemá seznam uživatelů — rozhovor vznikne jen tím, že se na něm vy dva domluvíte.',
      'chat.sent': 'odesláno',
      'chat.outbox': 'Čeká {n} zpráv — odejdou, jakmile bude {name} online.',
      'chat.outboxOne': 'Čeká 1 zpráva — odejde, jakmile bude {name} online.',
      'net.notStarted': 'Síť nespuštěna',
      'net.starting': 'Spouštím Tor…',
      'net.online': 'Online přes Tor',
      'net.offline': 'Offline',
      'net.connectedPeer': 'Spojeno s kontaktem',
      'net.connecting': 'Navazuji spojení…',
      'net.queued': 'Zpráva čeká na spojení',
      'net.receivingFile': 'Přijímám soubor…',
      'net.sendingFile': 'Odesílám soubor…',
      'net.error': 'Chyba sítě',
      'net.torStarting': 'Připojuji se k síti Tor…',
      'net.attempt': 'Navazuji spojení… (pokus {a} z {b} — přes Tor to chvíli trvá)',
      'net.unreachable': 'Kontakt zatím nedosažitelný: {e}',
      'net.staleInvite':
          'Pozvánka je zastaralá: protějšek má teď jinou identitu. Vyžádej si novou pozvánku a přidej ho znovu.',
      'net.notRunning': 'Síť ještě neběží',
      'chat.delivered': 'doručeno',
      'add.title': 'Přidat kontakt',
      'add.help':
          'Vlož POZVÁNKU protějšku — dlouhý text začínající "umbra1:".\nZíská ji v Nastavení tlačítkem „Zkopírovat pozvánku".',
      'add.help2':
          'Samotné jméno ani krátký kód nestačí — pozvánka nese i adresu, na které je protějšek dosažitelný.',
      'add.paste': 'Vložit ze schránky',
      'add.cancel': 'Zrušit',
      'add.submit': 'Přidat',
      'add.notInvite':
          'Tohle není pozvánka. Potřebuješ celý text začínající "umbra1:", který ti protějšek zkopíruje v Nastavení.',
      'add.failed': 'Pozvánku se nepodařilo načíst.',
      'add.ok': 'Kontakt přidán — otevři chat a dej Připojit',
      'settings.title': 'Nastavení',
      'settings.yourCode': 'Tvůj kód — sdílej, ať tě lidi najdou',
      'settings.copyCode': 'Kopírovat kód',
      'settings.codeCopied': 'Kód zkopírován',
      'settings.copyInvite': 'Zkopírovat pozvánku',
      'settings.inviteNotReady': 'Pozvánka bude hotová po připojení k Toru',
      'settings.inviteCopied': 'Pozvánka zkopírována — pošli ji kontaktu',
      'settings.network': 'Síť (Tor onion service)',
      'settings.online': 'Online',
      'settings.offline': 'Offline',
      'settings.copyOnion': 'Kopírovat onion adresu',
      'settings.onionCopied': 'Onion adresa zkopírována',
      'settings.padding': 'Skrývání délky (padding)',
      'settings.paddingHelp':
          'Každá zpráva se vycpe na pevnou velikost, aby z délky nešlo nic vyčíst.',
      'settings.language': 'Jazyk',
      'update.title': 'Verze',
      'update.available': 'Vyšla verze {v}.',
      'update.dialogTitle': 'Nová verze {v}',
      'update.dialogBody':
          'Stáhne se přes Tor a nainstaluje jen tehdy, když je podepsaná autorem. Zprávy, kontakty ani historie se nijak nedotkne.',
      'update.install': 'Aktualizovat',
      'update.retry': 'Zkusit znovu',
      'update.later': 'Později',
      'update.whatsNew': 'Co se změnilo',
      'update.workingTitle': 'Aktualizuji…',
      'update.starting': 'Spouštím stahování přes Tor…',
      'update.downloadingPct': 'Stahuji přes Tor… {pct} %',
      'update.downloadedOf': '({got} z {total} MB)',
      'update.verifying': 'Ověřuji podpis…',
      'update.checking': 'Kontroluji aktualizace přes Tor…',
      'update.upToDate': 'Máš nejnovější verzi.',
      'update.downloading': 'Stahuji verzi {v}…',
      'update.ready': 'Verze {v} je nainstalovaná — použije se po restartu.',
      'update.failed': 'Aktualizace neproběhla: {e}',
      'update.restart': 'Restartovat',
      'update.banner': 'Je připravená nová verze ({v}).',
      'groups.create': 'Nová skupina',
      'groups.createButton': 'Vytvořit skupinu',
      'groups.name': 'Název skupiny',
      'groups.pick': 'Kdo v ní bude',
      'groups.noContacts': 'Nejdřív si přidej kontakt — skupina se staví z kontaktů.',
      'groups.noCandidates': 'Všechny tvoje kontakty už ve skupině jsou.',
      'groups.addMember': 'Přidat člena',
      'groups.leave': 'Opustit skupinu',
      'groups.leaveTitle': 'Opustit skupinu?',
      'groups.leaveBody':
          'Ostatním se pošle, že jsi odešel, a skupina i její historie se z tohoto počítače smaže.',
      'groups.memberLine': '{n} členů • {online} online',
      'groups.you': 'Ty',
      'groups.onlineOnly':
          'Skupinová zpráva dojde těm, kdo jsou právě online — není žádný server, který by ji podržel.',
      'settings.autostart': 'Spouštět s Windows',
      'settings.autostartHelp':
          'NullChat se spustí po přihlášení, takže jsi dostupný i bez ručního zapnutí.',
      'settings.autostartFailed': 'Windows změnu nepřijaly.',
      'settings.theme': 'Barevný motiv',
      'settings.themeHelp':
          'Vyber si hotový motiv, nebo si namíchej vlastní barvu — celá aplikace se podle ní přebarví.',
      'settings.themeCustom': 'Vlastní barva',
      'settings.themeCustomTitle': 'Vlastní barva',
      'settings.themeHue': 'Odstín',
      'settings.themeSaturation': 'Sytost',
      'settings.themePreview': 'Náhled',
      'theme.mint': 'Mátový',
      'theme.azure': 'Modrý',
      'theme.violet': 'Fialový',
      'theme.amber': 'Jantarový',
      'theme.rose': 'Růžový',
      'theme.day': 'Denní',
      'theme.custom': 'Vlastní',
      'settings.disclaimer':
          'NullChat je experimentální a zatím bez nezávislého bezpečnostního auditu. Nespoléhej na ni tam, kde jde o život.',
      'devices.title': 'Zařízení',
      'devices.subtitle': 'aktivní • podepsané tvým klíčem, odvolatelné',
      'devices.fingerprint': 'Otisk tvé identity',
      'devices.thisDevice': 'Toto zařízení',
      'devices.revoked': 'Odvoláno',
      'devices.revoke': 'Odvolat',
      'devices.lastSeen': 'naposledy',
      'devices.revokeTitle': 'Odvolat zařízení?',
      'devices.revokeBody':
          'Zařízení ztratí přístup. Tvým kontaktům se rozešle podepsané odvolání, aby mu přestali důvěřovat.',
      'accounts.title': 'Vyber účet',
      'accounts.subtitle': 'Každý účet má vlastní identitu, kontakty i historii.',
      'accounts.add': 'Nový účet',
      'accounts.unnamed': 'Účet bez jména',
      'accounts.autoOn': 'Přihlašuje se sám',
      'accounts.autoOff': 'Ptá se na frázi',
      'accounts.remember': 'Na tomto počítači se přihlašovat automaticky',
      'accounts.rememberHelp':
          'Fráze se uloží zašifrovaná pro tvůj účet ve Windows. Kdo se dostane do tvých Windows, dostane se i sem.',
      'accounts.back': 'Zpět na účty',
      'accounts.remove': 'Smazat',
      'accounts.removeTitle': 'Smazat tento účet?',
      'accounts.removeBody':
          'jeho identita, kontakty i historie zpráv na tomto počítači budou vymazány. Nelze vzít zpět.',
      'accounts.switch': 'Přepnout účet',
      'accounts.signOut': 'Odhlásit se',
      'accounts.createTitle': 'Nový účet',
      'common.cancel': 'Zrušit',
      'common.save': 'Uložit',
      'common.close': 'Zavřít',
      'duress.title': 'Nouzové fráze',
      'duress.intro':
          'Tento účet může odpovídat víc než jedné frázi. Nastav žádnou, jednu '
          'nebo obě — v souboru není nikde napsáno, kolik jich je, a NullChat se '
          'chová úplně stejně, ať zadáš kteroukoli.',
      'duress.decoy.title': 'Nastrčený účet',
      'duress.decoy.body':
          'Otevře oddělenou historii s vlastními kontakty a zprávami. Tvoje '
          'skutečné konverzace z něj nejsou jen schované — jsou nedosažitelné '
          'a vyhledávání z nich nenajde nic. Vyplň ho běžným povídáním, ať '
          'nevypadá naaranžovaně.',
      'duress.wipe.title': 'Smazat po zadání',
      'duress.wipe.body':
          'Zničí všechno, co nedokáže přečíst, a otevře se jako úplně nový '
          'účet. Nejde to vzít zpět a nic se nepotvrzuje — právě o to jde. '
          'Soubor si drží velikost, takže na něm není nic, co by vypadalo '
          'čerstvě vyprázdněně.',
      'duress.set': 'Nastaveno',
      'duress.none': 'Žádná — účet otevírá jedna fráze',
      'duress.count': 'Nastaveno: {n}',
      'duress.setUp': 'Nastavit',
      'duress.remove': 'Zrušit',
      'duress.fill': 'Vyplnit konverzací',
      'duress.pickHint':
          'Aspoň 12 znaků a jiná než ta skutečná. Zvol něco, co pod tlakem '
          'napíšeš klidně a bez přemýšlení.',
      'duress.newPhrase': 'Nouzová fráze',
      'duress.repeat': 'Napiš ji znovu',
      'duress.mismatch': 'Zadání se neshodují.',
      'duress.removeHint':
          'Napiš nouzovou frázi, kterou chceš zrušit. Je to jediné, co se '
          'dostane k tomu, co vytvořila.',
      'duress.thatPhrase': 'Ta nouzová fráze',
      'duress.decoyPhrase': 'Fráze nastrčeného účtu',
      'duress.fillHint':
          'Zapíše se do nastrčeného účtu a rozprostře se do minulých týdnů. '
          'Přidej několik konverzací a občas si nastrčený účet otevři — '
          'historie, jejíž každá zpráva vznikla během jednoho odpoledne, '
          'nepřesvědčí nikoho.',
      'duress.fillWho': 'Jméno protějšku',
      'duress.fillLines': 'Jedna zpráva na řádek (střídají se strany)',
      'duress.fillEmpty': 'Zadej jméno a aspoň jednu zprávu.',
      'duress.fillDone': 'Přidáno {n} zpráv.',
      'duress.limits.title': 'Kde to přestává fungovat',
      'duress.limits.body':
          'Nepomůže proti nikomu, kdo si zkopíroval disk DŘÍV, než jsi frázi '
          'zadal — porovnáním obou kopií je vidět, co se změnilo, a nic, co '
          'poběží potom, tomu nezabrání. Neschová nastrčený účet, který je '
          'očividně prázdný, frázi zjevně jiné délky, ani stopy jinde v '
          'počítači: stránkovací soubor Windows, zálohovací program nebo '
          'náhledy obrázků.',
      'duress.notifications':
          'Dokud je nastavená nouzová fráze, oznámení se nepředávají Windows. '
          'Windows si každé zobrazené oznámení ukládá do vlastní databáze, kam '
          'žádná naše fráze nedosáhne, takže si je NullChat kreslí sama ve svém '
          'okně.',
      'waiting.title': 'Nevyřízené',
      'waiting.help':
          'Lidé, se kterými sis ještě nepsal. Přečti si, co poslali, a pak je pusť dál, nebo zablokuj.',
      'waiting.accept': 'Přijmout',
      'waiting.block': 'Zablokovat',
      'contacts.title': 'Kontakty',
      'contacts.subtitle': 'Lidé, které si držíš — z nich se skládá skupina.',
      'search.hint': 'Hledat lidi, skupiny a zprávy',
      'search.people': 'Lidé',
      'search.groups': 'Skupiny',
      'search.messages': 'Zprávy',
      'search.inGroup': 'skupina',
      'search.none': 'Na „{q}" nic nesedí.',
      'contact.where': 'Kde si píšete',
      'contact.messages': 'Co napsal',
      'contact.directChat': 'Přímý rozhovor',
      'contact.sharedGroups': 'Společné skupiny',
      'contact.noGroups': 'S tímhle člověkem nejsi v žádné skupině.',
      'contact.noMessages': 'Od tohohle člověka zatím nic.',
      'contact.all': 'Vše',
      'contact.direct': 'Jen přímé',
      'contact.fromGroups': 'Ze skupin',
      'chats.new': 'Nový',
      'contacts.empty':
          'Zatím žádné uložené kontakty. Ulož si někoho z rozhovoru a objeví se tady.',
      'contacts.blocked': 'Zablokovaní',
      'contacts.rename': 'Přejmenovat',
      'contacts.newName': 'Nové jméno',
      'contacts.save': 'Uložit do kontaktů',
      'contacts.forget': 'Odebrat z kontaktů',
      'contacts.unblock': 'Odblokovat',
      'contacts.delete': 'Smazat konverzaci',
      'contacts.deleteBody':
          'Odstraní {name} a všech {n} zpráv s ním z tohoto zařízení. Nejde to '
          'vzít zpět — zprávy se ze zašifrovaného úložiště smažou, neputují do '
          'koše. Protějšek si svou kopii ponechá.',
      'groups.rename': 'Přejmenovat skupinu',
      'notif.message': 'Nová zpráva',
      'notif.newFor': 'Máte novou zprávu na @{account}',
      'notif.title': 'Notifikace',
      'notif.detail': 'Zobrazovat odesílatele a text zprávy',
      'notif.detailHelp':
          'V notifikaci bude „odesílatel → účet: zpráva" místo pouhého oznámení, že něco přišlo.',
      'notif.detailLocked':
          'Jen pro účty, které se přihlašují automaticky. Tenhle si pokaždé řekne o frázi, takže jeho zprávy nenecháme svítit na obrazovce, u které nikdo není.',
      'notif.example': 'Notifikace bude vypadat takto: {example}',
      'notif.exampleFrom': 'Eva',
      'notif.exampleBody': 'sejdeme se v šest',
      'connecting.repair': 'Opravit a zkusit znovu',
      'connecting.repairHelp':
          'Smaže, co si Tor stáhl o síti, a začne znovu. Identita, adresa ani zprávy se nedotknou.',
      'connecting.repairing': 'Opravuji Tor a připojuji znovu…',
      'bridges.title': 'Mosty do Toru',
      'bridges.usingDefault': 'Používají se mosty přibalené k Umbře.',
      'bridges.usingCustom': 'Používají se tvoje vlastní mosty.',
      'bridges.help':
          'Přibalené mosty jsou veřejné, takže je cenzor může mít na seznamu. Když se Tor nepřipojí, vyžádej si osobní mosty na bridges.torproject.org (nebo e-mailem na bridges@torproject.org) a vlož je sem.',
      'bridges.hint': 'obfs4 1.2.3.4:443 OTISK cert=… iat-mode=0',
      'bridges.saved': 'Uloženo — projeví se při příštím startu.',
      'licenses.title': 'Licence',
      'licenses.subtitle': 'Z čeho je NullChat postavená a pod jakými podmínkami.',
      'licenses.header': 'NullChat je pod AGPL-3.0. Všechno, co používá, je tady.',
      'licenses.full':
          'Úplný seznam všech závislostí včetně nepřímých je v souboru THIRD-PARTY.md vedle zdrojového kódu.',
      'licenses.packages': 'Texty licencí balíčků',
      'tray.open': 'Otevřít Umbru',
      'tray.quit': 'Ukončit (přestaneš být dostupný)',
      'settings.trayHint':
          'Zavřením okna NullChat běží dál v liště, takže zprávy pořád chodí. Ukončit ji jde přes ikonu v liště.',
    },
  };
}
