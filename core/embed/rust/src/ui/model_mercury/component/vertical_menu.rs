use heapless::Vec;

use super::theme;
use crate::ui::{
    component::{base::Component, Event, EventCtx},
    display::Icon,
    geometry::Rect,
    model_mercury::component::button::{Button, ButtonMsg, IconText},
    shape::{Bar, Renderer},
};

pub enum VerticalMenuChoiceMsg {
    Selected(usize),
}

/// Number of buttons.
/// Presently, VerticalMenu holds only fixed number of buttons.
/// TODO: for scrollable menu, the implementation must change.
const N_ITEMS: usize = 3;

/// Number of visual separators between buttons.
const N_SEPS: usize = N_ITEMS - 1;

/// Fixed height of each menu button.
const MENU_BUTTON_HEIGHT: i16 = 64;

/// Fixed height of a separator.
const MENU_SEP_HEIGHT: i16 = 2;

type VerticalMenuButtons<T> = Vec<Button<T>, N_ITEMS>;
type AreasForSeparators = Vec<Rect, N_SEPS>;

pub struct VerticalMenu<T> {
    area: Rect,
    /// buttons placed vertically from top to bottom
    buttons: VerticalMenuButtons<T>,
    /// areas for visual separators between buttons
    areas_sep: AreasForSeparators,
}

impl<T> VerticalMenu<T>
where
    T: AsRef<str>,
{
    fn new(buttons: VerticalMenuButtons<T>) -> Self {
        Self {
            area: Rect::zero(),
            buttons,
            areas_sep: AreasForSeparators::new(),
        }
    }
    pub fn select_word(words: [T; 3]) -> Self {
        let mut buttons_vec = VerticalMenuButtons::new();
        for word in words {
            let button = Button::with_text(word).styled(theme::button_vertical_menu());
            unwrap!(buttons_vec.push(button));
        }
        Self::new(buttons_vec)
    }

    pub fn context_menu(options: [(T, Icon); 3]) -> Self {
        // TODO: this is just POC
        let mut buttons_vec = VerticalMenuButtons::new();
        for opt in options {
            let button_theme;
            match opt.1 {
                theme::ICON_CANCEL => {
                    button_theme = theme::button_vertical_menu_orange();
                }
                _ => {
                    button_theme = theme::button_vertical_menu();
                }
            }
            unwrap!(buttons_vec.push(
                Button::with_icon_and_text(IconText::new(opt.0, opt.1)).styled(button_theme)
            ));
        }
        Self::new(buttons_vec)
    }
}

impl<T> Component for VerticalMenu<T>
where
    T: AsRef<str>,
{
    type Msg = VerticalMenuChoiceMsg;

    fn place(&mut self, bounds: Rect) -> Rect {
        // VerticalMenu is supposed to be used in Frame, the remaining space is just
        // enought to fit 3 buttons separated by thin bars
        let height_bounds_expected = 3 * MENU_BUTTON_HEIGHT + 2 * MENU_SEP_HEIGHT;
        assert!(bounds.height() == height_bounds_expected);

        self.area = bounds;
        self.areas_sep.clear();
        let mut remaining = bounds;
        for i in 0..N_ITEMS {
            let (area_button, new_remaining) = remaining.split_top(MENU_BUTTON_HEIGHT);
            self.buttons[i].place(area_button);
            remaining = new_remaining;
            if i < N_SEPS {
                let (area_sep, new_remaining) = remaining.split_top(MENU_SEP_HEIGHT);
                unwrap!(self.areas_sep.push(area_sep));
                remaining = new_remaining;
            }
        }

        self.area
    }

    fn event(&mut self, ctx: &mut EventCtx, event: Event) -> Option<Self::Msg> {
        for (i, button) in self.buttons.iter_mut().enumerate() {
            if let Some(ButtonMsg::Clicked) = button.event(ctx, event) {
                return Some(VerticalMenuChoiceMsg::Selected(i));
            }
        }
        None
    }

    fn paint(&mut self) {
        // TODO remove when ui-t3t1 done
    }

    fn render<'s>(&'s self, target: &mut impl Renderer<'s>) {
        // render buttons separated by thin bars
        for button in &self.buttons {
            button.render(target);
        }
        for area in self.areas_sep.iter() {
            Bar::new(*area)
                .with_thickness(MENU_SEP_HEIGHT)
                .with_fg(theme::GREY_EXTRA_DARK)
                .render(target);
        }
    }

    #[cfg(feature = "ui_bounds")]
    fn bounds(&self, sink: &mut dyn FnMut(Rect)) {
        sink(self.area);
    }
}

#[cfg(feature = "ui_debug")]
impl<T> crate::trace::Trace for VerticalMenu<T>
where
    T: AsRef<str>,
{
    fn trace(&self, t: &mut dyn crate::trace::Tracer) {
        t.component("VerticalMenu");
        t.in_list("buttons", &|button_list| {
            for button in &self.buttons {
                button_list.child(button);
            }
        });
    }
}