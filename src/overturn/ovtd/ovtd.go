package ovtd

func Main() {

	opts := parse_args()
	if opts == nil {
		return
	}

	ctrl := NewController(opts)
	ctrl.Run()
}
