package nex

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Protocole Ranking (0x70). Sur Mario Kart 8 Deluxe il ne sert pas qu'aux
// classements : c'est lui qui porte le PROFIL des joueurs — identifiant Mii,
// nom Mii, pseudo en jeu, pays. Chacun dépose le sien (méthode 0x04) et
// demande celui des autres (méthode 0x16) en donnant une liste de PID.
//
// Relevé sur le serveur de Nintendo (capture du 2026-08-12) :
//
//	C->S  0x70/0x04  Buffer(132 octets) + u64      -> réponse vide
//	C->S  0x70/0x16  u32 nombre + N × u64 pid      -> u8 version, u32 taille,
//	                                                  u32 nombre, N × qBuffer
//
// Le bloc de 132 octets commence par 52 46 00 00, puis 16 octets d'identifiant
// Mii, puis le nom Mii en UTF-16 sur 22 octets, puis le pseudo en jeu. On ne le
// décode pas : on le stocke tel quel et on le rediffuse. C'est suffisant pour
// que pseudos et drapeaux réapparaissent, sans avoir à interpréter le format.
//
// Avant ce fichier, le dépôt était accepté puis jeté et la demande renvoyait une
// liste vide — mesuré en production : 17 746 dépôts et 16 273 demandes en sept
// jours, tous perdus. Aucun joueur n'apprenait donc jamais l'identité d'un autre.
const (
	ProtocolRanking        uint16 = 0x70
	MethodUploadCommonData uint32 = 0x4
	// MethodGetCommonData(unique_id u64) -> Buffer: a single player's own common
	// data, looked up by "unique ID" — which in this core IS the PID (see
	// utility.go's AcquireNexUniqueID: it hands out uint64(conn.PID) verbatim,
	// not a separate id space), so this reuses the same PID-keyed store
	// UploadCommonData/commonDataByPIDs already maintain. Mario Tennis Aces
	// calls this immediately after Register, before ever uploading anything —
	// left unanswered it's Core::NotImplemented -> the client's generic
	// 2306-0103 "an error has occurred", same signature already measured for
	// Splatoon 2's CloseParticipation above. An empty Buffer (no data on file
	// yet) is Nintendo's own answer for an unknown id, per commonDataByPIDs'
	// comment below — not a placeholder.
	MethodGetCommonData uint32 = 0x6

	// MethodUploadScore(RankingScoreData{category,score,order,update_mode,groups[],
	// param}, unique_id u64) -> empty ack. The STANDARD kinnay/NintendoClients wire
	// number (1) for score submission — distinct from methodRankingSubmitScore (0x11)
	// below, which is MK8's own measured number for the same concept. Mario Tennis
	// Aces uses 1: both players call it simultaneously right after a match, same
	// "unanswered -> 2306-0103" signature as everywhere else in this file.
	MethodUploadScore uint32 = 0x1

	// MethodGetRanking(mode u8, category u32, RankingOrderParam{order_calc,
	// group_index, group_num, time_scope u8; offset u32; count u8}, unique_id u64,
	// pid) -> RankingResult{data: List<RankingRankData>, total u32, since_time
	// DateTime}. Real bug found via live testing 2026-08-16: Mario Tennis Aces
	// calls this right after posting tournament entry data (DataStore
	// PostMetaBinary); left unanswered it silently killed the client with no
	// visible error for several reconnect attempts, matching the
	// PostMetaBinary/2306-0116 investigation above. An empty result (no
	// leaderboard data yet) is a valid, safe answer — same "empty is legitimate"
	// pattern as methodRankingGetCompetitionInfo/methodRankingCompetitionRanking.
	MethodGetRanking uint32 = 0x9

	// MethodGetCachedTopXRanking(category u32, RankingOrderParam) ->
	// RankingCachedResult{RankingResult + created_time, expired_time DateTime;
	// max_length u8}. Real bug found via live testing 2026-08-16: the Ranking
	// screen's period filters (World/National/Friend Ranking x "Last Month" etc)
	// use kinnay/NintendoClients' cached-topX variant instead of plain GetRanking
	// — left unhandled it's Core::NotImplemented (2306-0103) the instant a
	// period filter is picked, same signature as every other unanswered method
	// in this file. RankingCachedResult inherits RankingResult, so on the wire
	// it's TWO struct-header levels (base then derived) — same hierarchy framing
	// as MatchmakeSession/Gathering (see types.go's WriteStructure comment).
	MethodGetCachedTopXRanking uint32 = 0xE

	// methodRankingGetCompetitionInfo : liste des tournois. Sur la capture,
	// Nintendo rend 85 tournois ; sans tournoi chez nous, une liste vide.
	methodRankingGetCompetitionInfo uint32 = 0x12
	// methodRankingCompetitionRanking : classement d'UN tournoi. Laissée sans
	// réponse, elle renvoyait une ERREUR au jeu et cassait l'écran des tournois.
	// Nintendo répond lui-même une liste vide sur les tournois sans classement
	// (mesuré : 4 octets, 00 00 00 00) — c'est donc une réponse valide, pas un
	// pis-aller.
	methodRankingCompetitionRanking uint32 = 0x10
	// methodRankingCommonDataByPIDs : profils d'une liste de PID. Laissée sans
	// réponse, elle était le mur du mode mondial → 2618-0006.
	methodRankingCommonDataByPIDs uint32 = 0x16
	// methodRankingSubmitScore : dépôt du résultat en fin de course (161 octets).
	// Mesurée en production : les joueurs d'une même course l'envoient tous à la
	// MÊME seconde, à l'arrivée. Non gérée, elle rendait une erreur à chacun.
	methodRankingSubmitScore uint32 = 0x11
	// methodRankingSubmitTime : dépôt d'un temps de contre-la-montre (171 octets
	// sur la capture). Nintendo y répond un corps vide.
	methodRankingSubmitTime uint32 = 0x13

	// commonDataMaxLen borne ce qu'un client peut nous faire stocker. La capture
	// donne 132 octets ; on garde de la marge sans laisser un client pousser
	// n'importe quoi en mémoire.
	commonDataMaxLen = 4096
	// commonDataMaxEntries borne le nombre de PID qu'une seule demande peut
	// réclamer. Nintendo en demande neuf ; sans borne, une requête forgée ferait
	// produire une réponse arbitrairement grande.
	commonDataMaxEntries = 256
)

// commonDataStore garde le dernier profil déposé par chaque joueur.
//
// PERSISTÉ, et ce n'est pas un détail : un joueur ne redépose son profil qu'en
// passant en ligne. Gardé seulement en mémoire, un redémarrage vide la table et
// la liste d'amis se retrouve amputée de tous ceux qui ne se sont pas
// reconnectés depuis — constaté en jeu. Le fichier est donné par
// NEXTENDO_COMMON_DATA_FILE ; sans lui, on retombe sur le comportement mémoire.
var commonDataStore sync.Map // uint64 -> []byte

var (
	commonDataFile  = os.Getenv("NEXTENDO_COMMON_DATA_FILE")
	commonDataOnce  sync.Once
	commonDataDirty atomic.Bool
)

const (
	commonDataFlushEvery = 5 * time.Second
	// commonDataMaxStored borne le fichier : au-delà, on cesse d'ajouter plutôt
	// que de laisser grossir sans fin.
	commonDataMaxStored = 50000
)

// commonDataInit recharge les profils au démarrage et lance l'écriture différée.
func commonDataInit() {
	commonDataOnce.Do(func() {
		if commonDataFile == "" {
			return
		}
		if n, err := loadCommonData(commonDataFile); err == nil {
			fmt.Printf("[Ranking] profils restaurés : %d depuis %s\n", n, commonDataFile)
		}
		go commonDataFlusher()
	})
}

// loadCommonData recharge les profils d'un fichier dans la table. Rend le nombre
// d'entrées retenues. Une entrée illisible est ignorée sans faire échouer le
// reste : un fichier partiellement abîmé vaut mieux qu'aucun profil.
func loadCommonData(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var m map[string]string // pid décimal -> profil en base64
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, err
	}
	n := 0
	for k, v := range m {
		var pid uint64
		if _, err := fmt.Sscanf(k, "%d", &pid); err != nil {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(blob) == 0 || len(blob) > commonDataMaxLen {
			continue
		}
		commonDataStore.Store(pid, blob)
		n++
	}
	return n, nil
}

// writeCommonData écrit la table, par un fichier temporaire puis un
// remplacement atomique : une écriture interrompue ne laisse pas un fichier
// tronqué à la place des profils.
func writeCommonData(path string) error {
	out := map[string]string{}
	commonDataStore.Range(func(k, v any) bool {
		pid, ok1 := k.(uint64)
		blob, ok2 := v.([]byte)
		if ok1 && ok2 && len(out) < commonDataMaxStored {
			out[fmt.Sprintf("%d", pid)] = base64.StdEncoding.EncodeToString(blob)
		}
		return true
	})
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil { // 0600 : profils nominatifs
		return err
	}
	return os.Rename(tmp, path)
}

// commonDataFlusher écrit la table au plus une fois par intervalle, jamais sur
// le chemin d'une requête.
func commonDataFlusher() {
	t := time.NewTicker(commonDataFlushEvery)
	defer t.Stop()
	for range t.C {
		if !commonDataDirty.Swap(false) {
			continue
		}
		_ = writeCommonData(commonDataFile)
	}
}

// PutCommonData enregistre le profil d'un joueur. Exporté pour qu'un serveur de
// jeu puisse l'alimenter autrement (rejeu de capture, amorçage).
func PutCommonData(pid uint64, blob []byte) {
	if len(blob) == 0 || len(blob) > commonDataMaxLen {
		return
	}
	commonDataInit()
	cp := make([]byte, len(blob))
	copy(cp, blob)
	commonDataStore.Store(pid, cp)
	commonDataDirty.Store(true)
}

// CommonData rend le profil déposé par ce joueur, ou nil. Recharge le fichier
// au premier appel, pour qu'une demande arrivant avant tout dépôt trouve déjà
// les profils de la session précédente.
func CommonData(pid uint64) []byte {
	commonDataInit()
	if v, ok := commonDataStore.Load(pid); ok {
		if b, ok := v.([]byte); ok {
			return b
		}
	}
	return nil
}

// ForgetCommonData efface le profil d'un joueur (déconnexion).
func ForgetCommonData(pid uint64) { commonDataStore.Delete(pid) }

// RankingHandler traite le dépôt et la relecture des profils.
func RankingHandler() RMCHandler {
	return func(conn *Connection, req *RMCMessage) *RMCMessage {
		switch req.Method {
		case MethodUploadCommonData:
			return uploadCommonData(conn, req)
		case MethodGetCommonData:
			return getCommonData(conn, req)
		case MethodUploadScore:
			return uploadScore(conn, req)
		case MethodGetRanking:
			return getRanking(conn, req)
		case MethodGetCachedTopXRanking:
			return getCachedTopXRanking(conn, req)
		case methodRankingCommonDataByPIDs:
			return commonDataByPIDs(conn, req)
		case methodRankingGetCompetitionInfo:
			// Liste courte des tournois (identifiant + compteurs).
			return NewRMCSuccess(conn.Settings, ProtocolRanking, req.Method, req.CallID, TournamentSummaries())
		case methodRankingCompetitionRanking:
			return competitionRanking(conn, req)
		case methodRankingSubmitScore, methodRankingSubmitTime:
			// Dépôt d'un résultat. On ACQUITTE, corps vide, comme Nintendo le fait
			// pour les dépôts. On garde la trame telle quelle : le classement
			// (0x10) attend une forme différente — 5 enregistrements de 3312
			// octets — donc on ne peut pas la rediffuser en l'état. La conserver
			// permettra de la décoder sans redemander une course à personne.
			keepSubmittedScore(conn.PID, req.Method, req.Body)
			if req.Method == methodRankingSubmitScore {
				recordScore(conn.PID, req.Body) // alimente le classement du tournoi
			}
			// La réponse n'est PAS vide : Nintendo rend un seul octet à zéro
			// (mesuré sur la capture du 2026-08-12, méthode 0x11, len=1 « 00 »).
			return NewRMCSuccess(conn.Settings, ProtocolRanking, req.Method, req.CallID, []byte{0})
		default:
			return notImplemented(conn, ProtocolRanking, req)
		}
	}
}

// uploadCommonData retient le profil déposé. La réponse reste vide, comme chez
// Nintendo : la méthode ne sert qu'à publier.
func uploadCommonData(conn *Connection, req *RMCMessage) *RMCMessage {
	in := NewStreamIn(req.Body, conn.Settings)
	blob := in.Buffer()
	if in.Err() == nil {
		PutCommonData(conn.PID, blob)
	}
	return NewRMCSuccess(conn.Settings, ProtocolRanking, req.Method, req.CallID, nil)
}

// uploadScore answers the standard UploadScore(1): keep-and-ack, unconditionally
// — like methodRankingSubmitScore below, NOT a hard decode. A first attempt at
// strictly parsing kinnay/NintendoClients' documented RankingScoreData{category,
// score,order,update_mode,groups[],param}+unique_id shape hard-failed with
// Core::InvalidArgument for a real Mario Tennis Aces client (live-tested
// 2026-08-16): its actual body doesn't match that layout exactly (extra/missing
// field, or a different groups/param encoding — not yet decoded). Nintendo's own
// server doesn't echo anything back here either way, so there's nothing riding
// on getting the exact fields right immediately — store the raw body now,
// decode it properly once captured, same as methodRankingSubmitScore already
// does for MK8.
func uploadScore(conn *Connection, req *RMCMessage) *RMCMessage {
	s := conn.Settings
	fmt.Printf("[Ranking] UploadScore pid=%d bodyLen=%d body=%x\n", conn.PID, len(req.Body), req.Body)
	keepSubmittedScore(conn.PID, req.Method, req.Body)
	return NewRMCSuccess(s, ProtocolRanking, req.Method, req.CallID, nil)
}

// rankingResult is GetRanking's response. Real bug found via live testing
// 2026-08-16: this method's return type is RankingResult, a Structure
// (data List<RankingRankData>, total u32, since_time DateTime) — under NEX
// 4.0's struct-header framing (types.go's WriteStructure) that means the
// whole thing needs its own [u8 version][u32 length] wrapper on the wire, not
// just the three raw fields back to back. The first implementation wrote the
// raw fields directly; the client read the missing version byte as the top
// of data's u32 count and desynced every field after it, surfacing as
// 2306-0116 Core::BufferOverflow (the client overrunning its own read
// buffer) the instant GetRanking answered — which is what was silently
// killing the tournament-entry flow, not PostMetaBinary as first suspected.
// Confirmed by cross-checking kinnay/NintendoClients' common.Structure.encode:
// every Structure subclass gets this per-level header, RankingResult included.
type rankingResult struct {
	Total     uint32
	SinceTime uint64
}

// Levels implements Structure. data (List<RankingRankData>) is always empty
// today — no scores tracked yet, UploadScore just stores the raw submission
// rather than feeding a ranking table — so it's written inline rather than
// modeling RankingRankData for a case that never has elements yet.
func (r *rankingResult) Levels() []Level {
	return []Level{{
		Save: func(o *StreamOut) {
			WriteList(o, []struct{}{}, func(*StreamOut, struct{}) {}) // data: empty
			o.U32(r.Total)
			o.DateTime(r.SinceTime)
		},
	}}
}

// getRanking answers GetRanking with an empty leaderboard (see rankingResult
// above for why it must be wrapped, not raw fields). Doesn't bother decoding
// the request: nothing in it changes an empty answer, and every other method
// in this file that reaches this point already tolerates a request it can't
// fully interpret.
func getRanking(conn *Connection, req *RMCMessage) *RMCMessage {
	s := conn.Settings
	out := NewStreamOut(s)
	out.Add(&rankingResult{SinceTime: NowDateTime().Value()})
	return NewRMCSuccess(s, ProtocolRanking, req.Method, req.CallID, out.Bytes())
}

// rankingCachedResult is GetCachedTopXRanking's response. It inherits
// RankingResult (data/total/since_time) and adds its own level
// (created_time, expired_time, max_length) — two struct-header levels on the
// wire, base then derived, mirroring RankingResult/rankingResult above.
type rankingCachedResult struct {
	Total       uint32
	SinceTime   uint64
	CreatedTime uint64
	ExpiredTime uint64
	MaxLength   uint8
}

// Levels implements Structure. data is always empty, same reasoning as
// rankingResult above.
func (r *rankingCachedResult) Levels() []Level {
	return []Level{
		{ // RankingResult's level
			Save: func(o *StreamOut) {
				WriteList(o, []struct{}{}, func(*StreamOut, struct{}) {}) // data: empty
				o.U32(r.Total)
				o.DateTime(r.SinceTime)
			},
		},
		{ // RankingCachedResult's own level
			Save: func(o *StreamOut) {
				o.DateTime(r.CreatedTime)
				o.DateTime(r.ExpiredTime)
				o.U8(r.MaxLength)
			},
		},
	}
}

// getCachedTopXRanking answers the Ranking screen's period-filtered views
// ("Last Month" etc) with an empty cached leaderboard — same "empty is a
// legitimate answer, nothing tracked yet" reasoning as getRanking above.
// Doesn't decode the request (category + RankingOrderParam): nothing in it
// changes an empty answer.
func getCachedTopXRanking(conn *Connection, req *RMCMessage) *RMCMessage {
	s := conn.Settings
	now := NowDateTime().Value()
	out := NewStreamOut(s)
	out.Add(&rankingCachedResult{SinceTime: now, CreatedTime: now, ExpiredTime: now})
	return NewRMCSuccess(s, ProtocolRanking, req.Method, req.CallID, out.Bytes())
}

// getCommonData answers GetCommonData(unique_id): the caller's own stored
// common data, or an empty Buffer if nothing's been uploaded yet.
func getCommonData(conn *Connection, req *RMCMessage) *RMCMessage {
	s := conn.Settings
	in := NewStreamIn(req.Body, s)
	uniqueID := in.U64()
	if in.Err() != nil {
		return NewRMCError(s, ProtocolRanking, req.CallID, ResultCoreInvalidArgument)
	}
	out := NewStreamOut(s)
	out.Buffer(CommonData(uniqueID))
	return NewRMCSuccess(s, ProtocolRanking, req.Method, req.CallID, out.Bytes())
}

// commonDataByPIDs rend, pour chaque PID demandé et DANS L'ORDRE, le profil
// stocké — ou une entrée vide. L'ordre compte : le client associe la n-ième
// réponse au n-ième PID de sa demande. Nintendo renvoie lui aussi des entrées
// vides pour les joueurs qu'il ne connaît pas ; c'est une réponse valide.
func commonDataByPIDs(conn *Connection, req *RMCMessage) *RMCMessage {
	s := conn.Settings

	// Repli : la liste vide que cette méthode renvoyait avant qu'on stocke quoi
	// que ce soit. Laissée SANS réponse, elle était le mur du mode mondial
	// (2618-0006) ; on ne renvoie donc jamais d'erreur ici, quoi qu'on reçoive.
	vide := func() *RMCMessage {
		out := NewStreamOut(s)
		out.U32(0)
		return NewRMCSuccess(s, ProtocolRanking, req.Method, req.CallID, out.Bytes())
	}

	if len(req.Body) < 4 {
		return vide()
	}
	in := NewStreamIn(req.Body, s)
	count := in.U32()
	if in.Err() != nil || count == 0 || count > commonDataMaxEntries {
		return vide()
	}

	body := NewStreamOut(s)
	body.U32(count)
	for i := uint32(0); i < count; i++ {
		pid := in.PID()
		if in.Err() != nil {
			return vide()
		}
		body.QBuffer(CommonData(pid))
	}

	// Enveloppe relevée sur la capture : version puis taille du contenu.
	out := NewStreamOut(s)
	out.U8(0)
	out.U32(uint32(len(body.Bytes())))
	out.Write(body.Bytes())
	return NewRMCSuccess(s, ProtocolRanking, req.Method, req.CallID, out.Bytes())
}

// scoresStore garde le dernier résultat déposé par chaque joueur, par méthode.
// Il n'alimente PAS encore le classement : celui-ci attend une forme différente
// (5 enregistrements de 3312 octets sur la capture) qu'on n'a pas décodée. On
// conserve donc les trames pour les analyser hors ligne, sans avoir à redemander
// une course à qui que ce soit — c'est ce qui a manqué à chaque fois qu'il a
// fallu relancer une capture.
var scoresStore sync.Map // clé "pid/méthode" -> []byte

// keepSubmittedScore retient un dépôt. Borné comme le reste : un client ne doit
// pas pouvoir faire grossir la mémoire à volonté.
func keepSubmittedScore(pid uint64, method uint32, body []byte) {
	if len(body) == 0 || len(body) > commonDataMaxLen {
		return
	}
	cp := make([]byte, len(body))
	copy(cp, body)
	scoresStore.Store(fmt.Sprintf("%d/%d", pid, method), cp)
}

// SubmittedScore rend le dernier résultat déposé par ce joueur pour cette
// méthode, ou nil. Exporté pour le tableau de bord et l'analyse.
func SubmittedScore(pid uint64, method uint32) []byte {
	if v, ok := scoresStore.Load(fmt.Sprintf("%d/%d", pid, method)); ok {
		if b, ok := v.([]byte); ok {
			return b
		}
	}
	return nil
}
