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
      const text = elm.getElementsByTagName('p')[0].innerHTML
      const parent = elm.parentNode
      const tempDiv = document.createElement('div')
      tempDiv.innerHTML = `<div class="admonitionblock ${type}">
      <table>
        <tbody>
          <tr>
            <td class="icon">
              <i class="fa icon-${type}" title="${type}"></i>
            </td>
            <td class="content">
              ${text}
            </td>
          </tr>
        </tbody>
      </table>
    </div>`
  
      const input = tempDiv.childNodes[0]
      parent.replaceChild(input, elm)
    }
  })
