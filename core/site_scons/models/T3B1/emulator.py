from __future__ import annotations

from .. import get_hw_model_as_number


def configure(
    env: dict,
    features_wanted: list[str],
    defines: list[str | tuple[str, str]],
    sources: list[str],
    paths: list[str],
) -> list[str]:

    features_available: list[str] = []
    board = "T3B1/boards/t3b1-unix.h"
    hw_model = get_hw_model_as_number("T3B1")
    hw_revision = 0
    mcu = "STM32U585xx"

    defines += ["FRAMEBUFFER", "DISPLAY_MONO"]
    features_available.append("framebuffer")
    features_available.append("display_mono")

    defines += [mcu]
    defines += [f'TREZOR_BOARD=\\"{board}\\"']
    defines += [f"HW_MODEL={hw_model}"]
    defines += [f"HW_REVISION={hw_revision}"]
    defines += [f"MCU_TYPE={mcu}"]
    defines += ["FLASH_BIT_ACCESS=1"]
    defines += ["FLASH_BLOCK_WORDS=1"]

    if "sbu" in features_wanted:
        sources += ["embed/trezorhal/unix/sbu.c"]
    defines += ["USE_SBU=1"]

    if "optiga" in features_wanted:
        sources += ["embed/trezorhal/unix/optiga_hal.c"]
        sources += ["embed/trezorhal/unix/optiga.c"]
        features_available.append("optiga")
    defines += ["USE_OPTIGA=1"]

    if "input" in features_wanted:
        sources += ["embed/trezorhal/unix/button.c"]
        features_available.append("button")
    defines += ["USE_BUTTON=1"]

    sources += ["embed/trezorhal/stm32u5/layout.c"]

    return features_available
