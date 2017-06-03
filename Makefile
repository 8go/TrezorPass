UI_GENERATED := \
	ui_main_window.py \
	ui_initialize_dialog.py \
    ui_add_group_dialog.py \
	ui_add_password_dialog.py \
	ui_trezor_chooser_dialog.py \
	ui_trezor_pin_dialog.py \
    ui_trezor_passphrase_dialog.py \
    #end of UI_GENERATED

all: $(UI_GENERATED)

ui_%.py: %.ui
	pyuic5 -o $@ $<


clean:
	rm -f $(UI_GENERATED)
	rm -f *.pyc
	rm -rf __pycache__
