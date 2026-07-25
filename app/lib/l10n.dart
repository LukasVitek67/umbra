// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Minimal two-language support. English is the default so the app is usable by
// anyone who receives it; Czech can be switched on in Settings and the choice
// is remembered next to the app's data.

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

/// Notifies the whole app when the language changes.
final ValueNotifier<String> languageNotifier = ValueNotifier<String>('en');

class L {
  static String _lang = 'en';
  static File? _file;

  static String get lang => _lang;

  /// Load the stored preference (call once at startup).
  static Future<void> load() async {
    try {
      final dir = await getApplicationSupportDirectory();
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
      'onboard.passphrase': 'Passphrase (min. 8 characters)',
      'onboard.repeat': 'Repeat passphrase',
      'onboard.create.button': 'Create identity',
      'onboard.unlock.button': 'Unlock',
      'onboard.forgot': 'Forgot passphrase — create a new identity',
      'nav.chats': 'Chats',
      'nav.devices': 'Devices',
      'nav.settings': 'Settings',
      'connecting.title': 'Connecting to Tor',
      'connecting.subtitle':
          'Umbra needs a Tor connection before it can reach anyone. Nothing here needs your attention — it just takes a while.',
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
      'chat.verify': 'Verify',
      'chat.compose': 'Write a message…',
      'chat.attach': 'Send a file (encrypted)',
      'chat.showFile': 'Show in folder',
      'settings.picture': 'Profile picture',
      'settings.pickPicture': 'Choose picture',
      'settings.removePicture': 'Remove',
      'chat.pending': 'waiting to connect',
      'chat.waiting': 'waiting for them',
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
      'update.later': 'Later',
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
          'Umbra launches when you sign in, so you are reachable without opening it by hand.',
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
          'Umbra is experimental and has not been independently audited. Do not rely on it where lives are at stake.',
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
      'waiting.title': 'Waiting for you',
      'waiting.help':
          'People you have not talked to before. Read what they wrote, then let them in or block them.',
      'waiting.accept': 'Accept',
      'waiting.block': 'Block',
      'contacts.title': 'Contacts',
      'contacts.empty':
          'No saved contacts yet. Save someone from a conversation and they show up here.',
      'contacts.blocked': 'Blocked',
      'contacts.rename': 'Rename',
      'contacts.newName': 'New name',
      'contacts.save': 'Save to contacts',
      'contacts.forget': 'Remove from contacts',
      'contacts.unblock': 'Unblock',
      'groups.rename': 'Rename group',
      'notif.message': 'New message',
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
      'onboard.passphrase': 'Přístupová fráze (min. 8 znaků)',
      'onboard.repeat': 'Zopakuj frázi',
      'onboard.create.button': 'Vytvořit identitu',
      'onboard.unlock.button': 'Odemknout',
      'onboard.forgot': 'Zapomenutá fráze — založit novou identitu',
      'nav.chats': 'Chaty',
      'nav.devices': 'Zařízení',
      'nav.settings': 'Nastavení',
      'connecting.title': 'Připojuji se k Toru',
      'connecting.subtitle':
          'Umbra potřebuje spojení se sítí Tor, než na někoho dosáhne. Nic nemusíš dělat — jen to chvíli trvá.',
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
      'chat.verify': 'Ověřit',
      'chat.compose': 'Napiš zprávu…',
      'chat.attach': 'Poslat soubor (šifrovaně)',
      'chat.showFile': 'Zobrazit ve složce',
      'settings.picture': 'Profilový obrázek',
      'settings.pickPicture': 'Vybrat obrázek',
      'settings.removePicture': 'Odebrat',
      'chat.pending': 'čeká na spojení',
      'chat.waiting': 'čeká na protějšek',
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
      'update.later': 'Později',
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
          'Umbra se spustí po přihlášení, takže jsi dostupný i bez ručního zapnutí.',
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
          'Umbra je experimentální a zatím bez nezávislého bezpečnostního auditu. Nespoléhej na ni tam, kde jde o život.',
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
      'waiting.title': 'Nevyřízené',
      'waiting.help':
          'Lidé, se kterými sis ještě nepsal. Přečti si, co poslali, a pak je pusť dál, nebo zablokuj.',
      'waiting.accept': 'Přijmout',
      'waiting.block': 'Zablokovat',
      'contacts.title': 'Kontakty',
      'contacts.empty':
          'Zatím žádné uložené kontakty. Ulož si někoho z rozhovoru a objeví se tady.',
      'contacts.blocked': 'Zablokovaní',
      'contacts.rename': 'Přejmenovat',
      'contacts.newName': 'Nové jméno',
      'contacts.save': 'Uložit do kontaktů',
      'contacts.forget': 'Odebrat z kontaktů',
      'contacts.unblock': 'Odblokovat',
      'groups.rename': 'Přejmenovat skupinu',
      'notif.message': 'Nová zpráva',
    },
  };
}
