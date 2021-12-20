package pgmock_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/win-t/pgmock"
)

var ctx = context.Background()

func TestAll(t *testing.T) {
	if testing.Short() {
		t.Skipf("Short test")
	}

	if !pgmock.DockerAvailable() && os.Getenv("CI") == "" {
		t.Skipf("Docker is not available")
	}

	var random [16]byte
	for {
		if _, err := rand.Read(random[:]); err == nil {
			break
		}
	}
	ctrName := fmt.Sprintf("pgmock-%s", strings.ToLower(hex.EncodeToString(random[:])))
	testController(ctrName, false)
	_, err := exec.Command("docker", "stop", "-t", "1", ctrName).Output()
	check(err)
	testController(ctrName, false)
	testController(ctrName, true)
}

func testController(ctrName string, destroy bool) {
	c, err := pgmock.NewController(ctrName, 14, func(firstRun bool, connURL string) error {
		if firstRun {
			conn, err := pgx.Connect(ctx, connURL)
			check(err)
			defer conn.Close(ctx)
			_, err = conn.Exec(ctx, `create table testtable(i integer)`)
			check(err)
			_, err = conn.Exec(ctx, `insert into testtable values (1234)`)
			check(err)
		}
		return nil
	})
	check(err)
	if destroy {
		defer c.DestroyContainer()
	} else {
		defer c.Close()
	}

	for i := 0; i < 2; i++ {
		testMock(c)
	}
}

func testMock(c *pgmock.Controller) {
	instance, err := c.Instantiate()
	check(err)
	defer instance.Destroy()

	conn, err := pgx.Connect(ctx, instance.ConnURL())
	check(err)
	defer conn.Close(ctx)

	var i int
	err = conn.QueryRow(ctx, `select i from testtable`).Scan(&i)
	check(err)
	if i != 1234 {
		panic("invalid value")
	}

	_, err = conn.Exec(ctx, `update testtable set i = 1000 where i = 1234`)
	check(err)

	err = conn.QueryRow(ctx, `select i from testtable`).Scan(&i)
	check(err)
	if i != 1000 {
		panic("invalid value")
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
