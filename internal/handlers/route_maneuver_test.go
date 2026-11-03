package handlers

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	routerv1 "github.com/swayrider/protos/router/v1"
)

func TestToManeuverResult_RoundaboutArms(t *testing.T) {
	got := toManeuverResult(&routerv1.Maneuver{
		RoundaboutExitAngles:  []int32{90, 0, 270},
		RoundaboutEntryAngles: []int32{30},
	})

	if want := []int{90, 0, 270}; !reflect.DeepEqual(got.RoundaboutExitAngles, want) {
		t.Errorf("RoundaboutExitAngles = %v, want %v", got.RoundaboutExitAngles, want)
	}
	if want := []int{30}; !reflect.DeepEqual(got.RoundaboutEntryAngles, want) {
		t.Errorf("RoundaboutEntryAngles = %v, want %v", got.RoundaboutEntryAngles, want)
	}

	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"roundabout_exit_angles":[90,0,270]`, `"roundabout_entry_angles":[30]`} {
		if !strings.Contains(string(body), field) {
			t.Errorf("JSON %s lacks %s", body, field)
		}
	}
}

func TestToManeuverResult_NoArmsLeavesTheFieldsOut(t *testing.T) {
	got := toManeuverResult(&routerv1.Maneuver{})

	if got.RoundaboutExitAngles != nil || got.RoundaboutEntryAngles != nil {
		t.Errorf("got %v / %v, want none", got.RoundaboutExitAngles, got.RoundaboutEntryAngles)
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "roundabout_") {
		t.Errorf("JSON %s must not mention roundabout fields when there are none", body)
	}
}
