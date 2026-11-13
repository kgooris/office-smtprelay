package notify

import "fmt"

// text returns the subject and body of an alert in the given language ("nl" or
// anything else for English). a, b and c are the facts of the alert.
func text(lang, kind, a, b, c string) (subject, body string) {
	nl := lang == "nl"
	pick := func(en, nlText string) string {
		if nl {
			return nlText
		}
		return en
	}
	footer := pick("\n\nThis message was sent automatically by office-smtprelay. You can change these alerts under Settings, Notifications.",
		"\n\nDit bericht werd automatisch verstuurd door office-smtprelay. Je kan deze meldingen aanpassen onder Instellingen, Meldingen.")
	switch kind {
	case KindMSError:
		subject = pick("[office-smtprelay] Problem with Microsoft 365", "[office-smtprelay] Probleem met Microsoft 365")
		body = pick("A message could not be delivered through Microsoft 365.\n\nReason code: %s\nDevice: %s\nDetail: %s\n\nOpen the Logs page of the relay for an explanation and what to do. Common causes are an expired client secret or permissions that have not been applied yet.",
			"Een bericht kon niet via Microsoft 365 worden afgeleverd.\n\nRedencode: %s\nToestel: %s\nDetail: %s\n\nOpen de pagina Logboek van de relay voor uitleg en wat je kan doen. Vaak is het secret verlopen, of zijn rechten nog niet doorgevoerd.")
		body = fmt.Sprintf(body, a, b, c)
	case KindSecretExpiry:
		subject = pick("[office-smtprelay] Microsoft client secret expires soon", "[office-smtprelay] Microsoft-secret verloopt binnenkort")
		body = pick("The client secret of the Microsoft 365 connection expires on %[2]s (in %[1]s day(s)). When it expires, all mail stops.\n\nCreate a new secret in Microsoft Entra and enter it on the Microsoft 365 page of the relay. See Help, step 9.",
			"Het client secret van de Microsoft 365-koppeling verloopt op %[2]s (binnen %[1]s dag(en)). Zodra het verloopt, stopt alle mail.\n\nMaak een nieuw secret aan in Microsoft Entra en vul het in op de pagina Microsoft 365 van de relay. Zie Hulp, stap 9.")
		body = fmt.Sprintf(body, a, b)
	case KindClientBlock:
		subject = pick("[office-smtprelay] Device blocked: "+a, "[office-smtprelay] Toestel geblokkeerd: "+a)
		body = pick("The device \"%s\" reached its sending limit and is blocked for a while.\n\n%s\n\nA runaway or hijacked device can cause this. Check the device; you can lift the block on its Limits tab.",
			"Het toestel \"%s\" haalde zijn verzendlimiet en is een tijd geblokkeerd.\n\n%s\n\nDit kan komen door een op hol geslagen of gekaapt toestel. Controleer het toestel; je kan de blokkade opheffen op het tabblad Limieten.")
		body = fmt.Sprintf(body, a, b)
	case KindPaused:
		if a == "resumed" {
			subject = pick("[office-smtprelay] Sending resumed", "[office-smtprelay] Verzending hervat")
			body = pick("Sending through the relay was resumed.", "De verzending via de relay werd hervat.")
		} else {
			subject = pick("[office-smtprelay] Sending paused", "[office-smtprelay] Verzending gepauzeerd")
			body = pick("All sending through the relay was paused (emergency stop). Devices are told to try again later.",
				"Alle verzending via de relay werd gepauzeerd (noodknop). Toestellen krijgen het antwoord dat ze later opnieuw moeten proberen.")
		}
	default: // "test"
		subject = pick("[office-smtprelay] Test notification", "[office-smtprelay] Testmelding")
		body = pick("This is a test notification. If you can read this, alerts from the relay reach you.",
			"Dit is een testmelding. Als je dit leest, bereiken de meldingen van de relay je.")
	}
	return subject, body + footer
}
