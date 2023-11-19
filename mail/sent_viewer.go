package mail

import (
	"bytes"
	"context"
	"embed"
	_ "embed"
	"strconv"

	"github.com/blakewilliams/bat"
	"github.com/blakewilliams/fernet"
)

//go:embed views/*
var viewFS embed.FS

func RegisterSentMailViewer[T fernet.RequestContext](router fernet.Routable[T], mailer *Mailer) {
	renderer := bat.NewEngine(bat.HTMLEscape)
	err := renderer.AutoRegister(viewFS, "", ".html")
	if err != nil {
		panic(err)
	}

	router.Get("/_mailer", func(ctx context.Context, r T) {
		data := map[string]interface{}{
			"SentMail": mailer.SentMail,
		}

		childContent := new(bytes.Buffer)
		err := renderer.Render(childContent, "views/index.html", data)
		if err != nil {
			panic(err)
		}
		data["ChildContent"] = bat.Safe(childContent.String())

		renderer.Render(r.Response(), "views/layout.html", data)
	})

	router.Get("/_mailer/sent/:index", func(ctx context.Context, rc T) {
		strIndex := rc.Params()["index"]
		index, err := strconv.Atoi(strIndex)

		if err != nil {
			panic(err)
		}

		data := map[string]interface{}{
			"Mail":  mailer.SentMail[index],
			"Index": index,
		}

		childContent := new(bytes.Buffer)
		err = renderer.Render(childContent, "views/show.html", data)
		if err != nil {
			panic(err)
		}
		data["ChildContent"] = bat.Safe(childContent.String())

		renderer.Render(rc.Response(), "views/layout.html", data)
	})

	router.Get("/_mailer/sent/:index/content/:contentIndex/body", func(ctx context.Context, rc T) {
		strIndex := rc.Params()["index"]
		index, err := strconv.Atoi(strIndex)
		if err != nil {
			panic(err)
		}

		strContentIndex := rc.Params()["contentIndex"]
		contentIndex, err := strconv.Atoi(strContentIndex)
		if err != nil {
			panic(err)
		}

		rc.Response().Write([]byte(mailer.SentMail[index].Contents[contentIndex].Body))
	})
}
