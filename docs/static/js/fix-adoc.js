/*
 * Replace the default admonitions block with one that looks like the Antora output,
 * to apply similar styling via adoc.css. The default produced by Asciidoctor isn't
 * really nothing be proud of.
 *
 * Based on https://blog.anoff.io/2019-02-17-hugo-render-asciidoc/
 */
window.addEventListener('load', function () {
    const admonitions = document.getElementsByClassName('admonition-block')
    for (let i = admonitions.length - 1; i >= 0; i--) {
      const elm = admonitions[i]
      const type = elm.classList[1]

      const parent = elm.parentNode;

      // This is our temporary element, contains our newly constructed table for the admonition block.
      const tempDiv = document.createElement('div')
      tempDiv.innerHTML = `<div class="admonitionblock ${type}">
      <table>
        <tbody>
          <tr>
            <td class="icon">
              <i class="fa icon-${type}" title="${type}"></i>
            </td>
            <td class="content">
            </td>
          </tr>
        </tbody>
      </table>
      </div>`

      // Now copy the content of the original admonition block into our a table cell for the content.
      const content_td = tempDiv.getElementsByClassName('content')[0];

      while (elm.hasChildNodes()) {
        child = elm.removeChild(elm.firstChild);

        // Do not copy <h6 /> elements: these are used by the admonition block to hold the block name,
        // like "NOTE" or "WARNING" - but we don't need these anymore, as our new table shows an icon
        // instead. And it's very unlikely we would ever use <h6 /> for anything real in these blocks.
        if (child.tagName == 'H6') {
          continue;
        }

        content_td.appendChild(child);
      }

      // And the final switch, replace original block with our table.
      const input = tempDiv.childNodes[0];
      parent.replaceChild(input, elm);
    }
})
