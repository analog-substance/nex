package dns_guard_rail

import "testing"

func TestShouldInvestigateMore(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "should not scan guardrails host",
			args: args{
				"dadasd.cloudfront.net",
			},
			want: false,
		},
		{
			name: "should scan domain",
			args: args{
				"adasd.notcloudfront.net",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldInvestigateMore(tt.args.domain); got != tt.want {
				t.Errorf("ShouldInvestigateMore() = %v, want %v", got, tt.want)
			}
		})
	}
}
