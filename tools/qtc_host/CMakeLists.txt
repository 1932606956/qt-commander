# In-process host harness: a minimal Qt Widgets app that calls
# qt_commander_init() itself (no injection), so the embed/static path can be
# exercised end to end.  Built only with -DQTC_BUILD_HOST=ON.
add_executable(qtc-host main.cpp)
target_include_directories(qtc-host PRIVATE ${CMAKE_SOURCE_DIR}/src/library)
target_link_libraries(qtc-host PRIVATE
    Qt${QT_MAJOR_VERSION}::Core
    Qt${QT_MAJOR_VERSION}::Gui
    Qt${QT_MAJOR_VERSION}::Widgets)
if(QTC_STATIC)
    target_link_libraries(qtc-host PRIVATE qt-commander-static)
    target_compile_definitions(qtc-host PRIVATE QTC_HOST_LINK_STATIC=1)
endif()
if(MSVC)
    target_compile_options(qtc-host PRIVATE /utf-8)
endif()
