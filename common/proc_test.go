package common

import "testing"

func TestIsGoExecutable(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{name: "1", args: args{filename: "/root/workspace/pktlatency/testdata/https-request/https-request"}, want: true, wantErr: false},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsGoExecutable(tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsGoExecutable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsGoExecutable() = %v, want %v", got, tt.want)
			}
		})
	}
}
