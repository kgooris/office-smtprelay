package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/kgooris/office-smtprelay/internal/store"
)

func (s *Server) backupPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	v := view{Nav: true, Active: "backup", CSRF: sd.csrf}
	s.flashFromQuery(r, &v)
	s.render(w, r, http.StatusOK, "backup", v)
}

// backupExport sends the backup as a download. It is a POST so that the
// download needs the CSRF token and is never fetched by a link or an image.
func (s *Server) backupExport(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	b, err := s.d.Store.ExportBackup()
	if err != nil {
		s.fail(w, err)
		return
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		s.fail(w, err)
		return
	}
	name := "office-smtprelay-backup-" + s.now().Format("2006-01-02") + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	s.d.Logger.Printf("web UI: backup exported (%d device(s))", len(b.Clients))
	_, _ = w.Write(data)
}

func (s *Server) backupImport(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	fail := func(key string, status int) {
		v := view{Nav: true, Active: "backup", CSRF: sd.csrf}
		v.Flash, v.FlashKind = s.tr(r, key), "err"
		s.render(w, r, status, "backup", v)
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		fail("backup.err_file", http.StatusBadRequest)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 512<<10))
	if err != nil {
		fail("backup.err_file", http.StatusBadRequest)
		return
	}
	var b store.Backup
	if err := json.Unmarshal(data, &b); err != nil {
		fail("backup.err_file", http.StatusBadRequest)
		return
	}
	res, err := s.d.Store.ImportBackup(b)
	if err != nil {
		v := view{Nav: true, Active: "backup", CSRF: sd.csrf}
		v.Flash, v.FlashKind = s.tr(r, "backup.err_import", err.Error()), "err"
		s.render(w, r, http.StatusBadRequest, "backup", v)
		return
	}
	_ = s.d.Conn.ApplyPorts(s.d.Store.ExtraPorts()) // the backup may change the extra listeners
	s.d.Logger.Printf("web UI: backup imported: %d added, %d updated", res.Added, res.Updated)
	v := view{Nav: true, Active: "backup", CSRF: sd.csrf}
	v.Flash, v.FlashKind = s.tr(r, "backup.imported", res.Added, res.Updated), "ok"
	s.render(w, r, http.StatusOK, "backup", v)
}
