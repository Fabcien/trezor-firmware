from __future__ import annotations


def stm32u5_common_files(env, defines, sources, paths):
    defines += [
        ("STM32_HAL_H", '"<stm32u5xx.h>"'),
        ("FLASH_BLOCK_WORDS", "4"),
        ("USE_TRUSTZONE", "1"),
        ("CONFIDENTIAL", "'__attribute__((section(\".confidential\")))'"),
    ]

    paths += [
        "embed/trezorhal/stm32u5",
        "vendor/stm32u5xx_hal_driver/Inc",
        "vendor/cmsis_device_u5/Include",
        "vendor/cmsis_5/CMSIS/Core/Include",
    ]

    sources += [
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_cortex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_cryp.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_dma2d.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_dma.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_dma_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_dsi.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_exti.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_flash.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_flash_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_gfxmmu.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_gpio.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_gtzc.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_hash.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_hash_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_i2c.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_i2c_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_icache.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_ltdc.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_ltdc_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_pcd.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_pcd_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_pwr.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_pwr_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_rcc.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_rcc_ex.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_rtc.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_spi.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_hal_sram.c",
        "vendor/stm32u5xx_hal_driver/Src/stm32u5xx_ll_fmc.c",
    ]

    sources += [
        "embed/trezorhal/stm32u5/applet.c",
        "embed/trezorhal/stm32u5/board_capabilities.c",
        "embed/trezorhal/stm32u5/bootutils.c",
        "embed/trezorhal/stm32u5/entropy.c",
        "embed/trezorhal/stm32u5/flash.c",
        "embed/trezorhal/stm32u5/flash_otp.c",
        "embed/trezorhal/stm32u5/fwutils.c",
        "embed/trezorhal/stm32u5/layout.c",
        "embed/trezorhal/stm32u5/hash_processor.c",
        "embed/trezorhal/stm32u5/monoctr.c",
        "embed/trezorhal/stm32u5/mpu.c",
        "embed/trezorhal/stm32u5/option_bytes.c",
        "embed/trezorhal/stm32u5/pvd.c",
        "embed/trezorhal/stm32u5/random_delays.c",
        "embed/trezorhal/stm32u5/reset_flags.c",
        "embed/trezorhal/stm32u5/rng.c",
        "embed/trezorhal/stm32u5/secret.c",
        "embed/trezorhal/stm32u5/secure_aes.c",
        "embed/trezorhal/stm32u5/startup_init.c",
        "embed/trezorhal/stm32u5/syscall.c",
        "embed/trezorhal/stm32u5/syscall_dispatch.c",
        "embed/trezorhal/stm32u5/syscall_probe.c",
        "embed/trezorhal/stm32u5/syscall_stubs.c",
        "embed/trezorhal/stm32u5/syscall_verifiers.c",
        "embed/trezorhal/stm32u5/system.c",
        "embed/trezorhal/stm32u5/systask.c",
        "embed/trezorhal/stm32u5/systick.c",
        "embed/trezorhal/stm32u5/systimer.c",
        "embed/trezorhal/stm32u5/tamper.c",
        "embed/trezorhal/stm32u5/time_estimate.c",
        "embed/trezorhal/stm32u5/trustzone.c",
        "embed/trezorhal/stm32u5/unit_properties.c",
        "embed/trezorhal/stm32u5/vectortable.S",
    ]

    # boardloader needs separate assembler for some function unencumbered by various FW+bootloader hacks
    # this helps to prevent making a bug in boardloader which may be hard to fix since it's locked with write-protect
    env_constraints = env.get("CONSTRAINTS")
    if env_constraints and "limited_util_s" in env_constraints:
        sources += [
            "embed/trezorhal/stm32u5/limited_util.S",
        ]
    else:
        sources += [
            "embed/trezorhal/stm32u5/util.S",
        ]

    env.get("ENV")["SUFFIX"] = "stm32u5"
